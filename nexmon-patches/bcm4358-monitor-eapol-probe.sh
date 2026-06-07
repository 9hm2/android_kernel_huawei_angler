#!/usr/bin/env bash
# bcm4358-monitor-eapol-probe.sh — prove whether the EAPOL packet handed to
# nexmon's wl_monitor_radiotap is fragmented (p->len is only the first lbuf
# fragment, the rest hangs off p->next) rather than truly truncated.
#
# The firmware console (where a plain printf would land) is not readable at
# runtime on this build, so instead of printing we SMUGGLE the values out
# through the radiotap header into the kernel: for an EAPOL frame we overwrite
# the 8-byte TSF field of the outgoing nexmon radiotap header with a marker
#   bytes 0..3  = 0x4c4f5045 ("EPOL" LE-ish marker)
#   bytes 4..5  = p->len  (the firmware-reported first-fragment length)
#   bytes 6..7  = p->next (the lbuf index of the next fragment, 0 if none)
# The kernel side (dhd_rx_mon_pkt) recognises the marker and prints len/next to
# dmesg. If p->next != 0 for EAPOL, the frame is chained and the fix is to walk
# the chain; if p->next == 0, the data really is gone upstream.
#
# Inserts the marker write right after the radiotap header is built (after the
# dbm_antnoise assignment) and before the memcpy. Idempotent.
#
# Usage: bcm4358-monitor-eapol-probe.sh <path-to-monitormode.c>
set -euo pipefail

SRC="${1:?usage: $0 <monitormode.c>}"
[ -f "$SRC" ] || { echo "::warning::eapol-probe: $SRC not found, skipping"; exit 0; }

if grep -q "NEXMON-EAPOL-PROBE" "$SRC"; then
	echo "eapol-probe already present in $SRC, nothing to do"
	exit 0
fi

python3 - "$SRC" <<'PY'
import sys
path = sys.argv[1]
src = open(path).read()

probe = r'''
    /* NEXMON-EAPOL-PROBE: smuggle p->len and p->next out via the radiotap TSF
     * field for EAPOL frames, so the kernel can tell if the packet is chained
     * (p->next != 0) rather than truncated. */
    {
        unsigned char *pd = (unsigned char *) p->data;
        int _i, _eo = -1;
        int _scan = (p->len > 64) ? 64 : (int) p->len;
        for (_i = 0; _i + 8 <= _scan; _i++) {
            if (pd[_i]==0xaa && pd[_i+1]==0xaa && pd[_i+2]==0x03 &&
                pd[_i+3]==0x00 && pd[_i+4]==0x00 && pd[_i+5]==0x00 &&
                pd[_i+6]==0x88 && pd[_i+7]==0x8e) { _eo = _i; break; }
        }
        if (_eo >= 0) {
            /* sk_buff: short len @0x0C, unsigned short next @0x14 */
            unsigned short _next = *(volatile unsigned short *)
                                       (((unsigned char *) p) + 0x14);
            frame->tsf.tsf_l = 0x4c4f5045u;          /* marker */
            frame->tsf.tsf_h = ((unsigned int) p->len & 0xffff)
                             | (((unsigned int) _next & 0xffff) << 16);
        }
    }
'''

anchor = "frame->dbm_antnoise = sts->noise;"
if anchor not in src:
    print("::warning::eapol-probe: anchor not found; monitormode.c changed, skipping")
    sys.exit(0)

src = src.replace(anchor, anchor + "\n" + probe, 1)
open(path, "w").write(src)
print("eapol-probe: inserted NEXMON-EAPOL marker (len/next via radiotap TSF)")
PY
