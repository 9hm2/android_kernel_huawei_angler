#!/system/bin/sh
# bt-up.sh — bring the Nexus 6P (angler) on-board BCM4358 Bluetooth up as an
# HCI device for BlueZ/NetHunter.
#
# It starts D-Bus and the bluetooth service, power-cycles the radio, attaches
# the UART HCI (loading the BCM4358A3 patchram firmware), brings hci0 up, and
# reports each step in English. Re-runnable: it cleans up a previous attach
# first.
#
#   Usage:  ./bt-up.sh [-a AA:BB:CC:DD:EE:FF]   # optional spoofed BD address
#           ./bt-up.sh -d                       # down / detach instead
#
# Requires root (run from the Kali/NetHunter chroot as root).

DEV=/dev/ttyHS0
BAUD=3000000
HCI=hci0
# Where the BCM patchram firmware lives on angler, and where hciattach looks.
FW_SRC=/vendor/firmware/BCM4358A3_RFSW.hcd
FW_DST1=/lib/firmware/BCM4358A3.hcd
FW_DST2=/etc/firmware/BCM4358A3.hcd

SPOOF=""
ACTION="up"
while [ $# -gt 0 ]; do
    case "$1" in
        -a) SPOOF="$2"; shift 2 ;;
        -d) ACTION="down"; shift ;;
        -h|--help)
            echo "Usage: $0 [-a BD_ADDR] [-d]"
            echo "  -a BD_ADDR  spoof the controller address after bring-up"
            echo "  -d          take the controller down and detach"
            exit 0 ;;
        *)  echo "[!] Unknown option: $1"; exit 1 ;;
    esac
done

# --- helpers ---------------------------------------------------------------
ok()   { echo "[+] $*"; }
info() { echo "[*] $*"; }
warn() { echo "[!] $*"; }
die()  { echo "[x] $*"; exit 1; }

need_root() {
    [ "$(id -u)" = "0" ] || die "must run as root"
}

have() { command -v "$1" >/dev/null 2>&1; }

# --- teardown --------------------------------------------------------------
detach() {
    info "Detaching $HCI and stopping hciattach..."
    hciconfig "$HCI" down 2>/dev/null
    killall hciattach 2>/dev/null
    sleep 1
    ok "Bluetooth detached."
}

# ===========================================================================
need_root

if [ "$ACTION" = "down" ]; then
    detach
    exit 0
fi

echo "=== Nexus 6P (BCM4358) Bluetooth bring-up ==="

# 1. Tools present?
for t in hciattach hciconfig dbus-daemon; do
    have "$t" || warn "missing tool: $t (some steps may fail)"
done

# 2. Firmware in place (symlink the vendor .hcd where hciattach looks).
if [ -f "$FW_SRC" ]; then
    mkdir -p "$(dirname "$FW_DST1")" "$(dirname "$FW_DST2")" 2>/dev/null
    [ -f "$FW_DST1" ] || ln -sf "$FW_SRC" "$FW_DST1"
    [ -f "$FW_DST2" ] || ln -sf "$FW_SRC" "$FW_DST2"
    ok "Patchram firmware ready: $FW_SRC"
else
    warn "patchram firmware $FW_SRC not found - will attach without it"
fi

# 3. D-Bus: needed by bluetoothd / bluetoothctl.
if pidof dbus-daemon >/dev/null 2>&1; then
    ok "D-Bus already running (pid $(pidof dbus-daemon))."
else
    info "Starting D-Bus..."
    mkdir -p /run/dbus /var/run/dbus 2>/dev/null
    dbus-daemon --system --fork 2>/dev/null
    sleep 1
    if pidof dbus-daemon >/dev/null 2>&1; then
        ok "D-Bus started (pid $(pidof dbus-daemon))."
    else
        warn "D-Bus did not start; bluetoothctl may not work."
    fi
fi

# 4. bluetoothd service.
if pidof bluetoothd >/dev/null 2>&1; then
    ok "bluetoothd already running (pid $(pidof bluetoothd))."
else
    info "Starting bluetoothd..."
    if have service; then
        service bluetooth start >/dev/null 2>&1
    fi
    if ! pidof bluetoothd >/dev/null 2>&1; then
        # fall back to launching the daemon directly
        BTD="$(command -v bluetoothd || echo /usr/libexec/bluetooth/bluetoothd)"
        [ -x "$BTD" ] && "$BTD" --experimental >/dev/null 2>&1 &
        sleep 1
    fi
    if pidof bluetoothd >/dev/null 2>&1; then
        ok "bluetoothd started (pid $(pidof bluetoothd))."
    else
        warn "bluetoothd not running; hci0 will still work with hcitool/btmgmt."
    fi
fi

# 5. Clean any previous attach, then power-cycle the radio for a clean state.
killall hciattach 2>/dev/null
info "Power-cycling the Bluetooth radio (rfkill)..."
rfkill block bluetooth 2>/dev/null
sleep 1
rfkill unblock bluetooth 2>/dev/null
sleep 1
ok "Radio power-cycled."

# 6. Attach the UART HCI (loads the .hcd patchram firmware).
info "Attaching $HCI on $DEV @ ${BAUD} baud (loading firmware)..."
hciattach "$DEV" bcm43xx "$BAUD" flow &
ATTACH_PID=$!

# 7. Wait for hci0 to appear (firmware download takes a couple of seconds).
n=0
while [ $n -lt 10 ]; do
    if hciconfig "$HCI" >/dev/null 2>&1; then break; fi
    sleep 1
    n=$((n+1))
done

if ! hciconfig "$HCI" >/dev/null 2>&1; then
    warn "hci0 did not appear. Common fixes:"
    warn "  - re-run (the rfkill power-cycle often clears a stuck attach)"
    warn "  - try a lower download baud: edit BAUD=921600 in this script"
    die  "Bluetooth bring-up failed."
fi
ok "$HCI created (hciattach pid $ATTACH_PID)."

# 8. Bring it up.
info "Bringing $HCI up..."
hciconfig "$HCI" up 2>/dev/null
sleep 1

# 9. Optional address spoof.
if [ -n "$SPOOF" ]; then
    if have spooftooph; then
        info "Spoofing BD address -> $SPOOF ..."
        spooftooph -i "$HCI" -a "$SPOOF" >/dev/null 2>&1
        hciconfig "$HCI" up 2>/dev/null
        ok "Address spoofed."
    else
        warn "spooftooph not found; skipping address spoof."
    fi
fi

# 10. Final status.
echo
echo "=== Bluetooth is up ==="
hciconfig "$HCI" -a 2>/dev/null | sed 's/^/    /'
echo
ok "Ready. Try:  hcitool dev   |   hcitool lescan   |   bluetoothctl"
info "To take it down:  $0 -d"
