#!/usr/bin/env bash
# Recover the FULL EAPOL frame on the nexmon BCM4358 radiotap monitor path.
#
# Problem (proven with a 100% passive capture, pass01.cap):
#   In monitor mode the firmware passes management frames (beacons) and
#   PROTECTED data frames through FULL (encrypted data seen up to 1490 bytes),
#   but every UNPROTECTED data frame -- i.e. the EAPOL handshake -- is cut to a
#   fixed ~86 on-air bytes, losing exactly the M1 RSN PMKID and the M2/M3 MIC
#   that make WPA2 crackable. The cut is a software length cap: by the time the
#   frame reaches wl_monitor_radiotap() in
#       patches/bcm4358/<fwver>/nexmon/src/monitormode.c
#   p->len is already ~92 (the clone is just `memcpy(..., p->data+6, p->len-6)`).
#
# Why it is recoverable:
#   The DMA places the WHOLE frame in the lbuf regardless of type -- the 1490 B
#   protected frames arriving on this same path prove the buffer holds full
#   frames. So for a truncated EAPOL the rest of the body is still present in
#   p->data past p->len; only the length field was clamped. The real length is
#   carried in the 802.1X length field, which sits INSIDE the surviving ~86
#   bytes, so we can compute it and copy the full frame.
#
# Fix:
#   At the top of wl_monitor_radiotap(), detect an unprotected EAPOL data frame
#   (LLC/SNAP ethertype 0x888E) and, if its true length exceeds the truncated
#   p->len, restore p->len to the real value before the existing clone runs.
#   Bounded (<= 600) and only ever grows the length, so a wrong guess cannot
#   fault (the 2032 cap and lbuf size still bound the copy). Idempotent.
#
# Requires MONITOR_RADIOTAP mode (the driver's default), which routes through
# this patched function via the nexmon pkt_buf_get_skb hook.
#
# Usage: bcm4358-monitor-eapol-fulllen.sh <path-to-monitormode.c>
set -euo pipefail

SRC="${1:?usage: $0 <monitormode.c>}"

if [ ! -f "$SRC" ]; then
	echo "::warning::monitor eapol-fulllen: $SRC not found, skipping"
	exit 0
fi

if grep -q "EAPOL full-length recovery" "$SRC"; then
	echo "monitor eapol-fulllen already present in $SRC, nothing to do"
	exit 0
fi

python3 - "$SRC" <<'PY'
import sys

path = sys.argv[1]
with open(path) as f:
    src = f.read()

# Anchor: the opening of wl_monitor_hook(), the dispatcher that runs for EVERY
# monitor mode (RADIOTAP and IEEE80211) before the switch. Fixing p->len here
# means both the nexmon radiotap clone and the original ROM wl_monitor clone
# copy the full frame -- so the recovery is independent of the monitor value.
anchor = (
    "wl_monitor_hook(struct wl_info *wl, struct wl_rxsts *sts, struct sk_buff *p) {\n"
)
if anchor not in src:
    sys.stderr.write("monitor eapol-fulllen: wl_monitor_hook anchor not found; "
                     "firmware source layout may have changed\n")
    sys.exit(1)

recover = anchor + (
    "    // EAPOL full-length recovery: in monitor mode the firmware passes\n"
    "    // management frames and PROTECTED data frames through full (encrypted\n"
    "    // data seen up to 1490 B), but truncates every UNPROTECTED data frame\n"
    "    // -- i.e. the EAPOL handshake -- to a fixed ~86 on-air bytes, dropping\n"
    "    // the M1 RSN PMKID and the M2/M3 MIC needed to crack WPA2. The whole\n"
    "    // frame is still in the lbuf (the 1490 B protected frames on this same\n"
    "    // path prove the buffer holds full frames); only p->len was clamped.\n"
    "    // The true length lives in the 802.1X length field, inside the surviving\n"
    "    // bytes, so restore p->len before the clone (radiotap or ROM) runs.\n"
    "    // Only ever grows, bounded <= 600, so a wrong guess cannot fault.\n"
    "    if (p->len > 6) {\n"
    "        unsigned char *f = (unsigned char *)p->data + 6; // 802.11 frame\n"
    "        unsigned int fc = f[0] | (f[1] << 8);\n"
    "        if ((fc & 0x0C) == 0x08) {                       // type Data\n"
    "            unsigned int hdrlen = (fc & 0x80) ? 26 : 24; // +2 for QoS\n"
    "            unsigned int avail = p->len - 6;\n"
    "            if (avail > hdrlen + 12) {\n"
    "                unsigned char *llc = f + hdrlen;\n"
    "                if (llc[6] == 0x88 && llc[7] == 0x8E) {  // SNAP 0x888E\n"
    "                    unsigned char *x = llc + 8;          // 802.1X header\n"
    "                    // full frame = 802.11 hdr + LLC/SNAP + 802.1X hdr(4) +\n"
    "                    // 802.1X body + FCS(4). nexmon sets RADIOTAP_F_FCS, so\n"
    "                    // include the trailing FCS; any extra trailing bytes are\n"
    "                    // ignored by tshark/hcxpcapngtool (they use the 802.1X\n"
    "                    // length field), while a SHORT body is malformed.\n"
    "                    unsigned int real = hdrlen + 8 + 4 +\n"
    "                                        ((x[2] << 8) | x[3]) + 4;\n"
    "                    if (real + 6 > p->len && real + 6 <= 700)\n"
    "                        p->len = real + 6;\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
)

src = src.replace(anchor, recover, 1)

with open(path, "w") as f:
    f.write(src)
print(f"monitor eapol-fulllen: added EAPOL full-length recovery to {path}")
PY
