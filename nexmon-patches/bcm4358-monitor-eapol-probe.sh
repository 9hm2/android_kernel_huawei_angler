#!/usr/bin/env bash
# bcm4358-monitor-eapol-probe.sh — test whether the FULL EAPOL is recoverable
# inside nexmon's wl_monitor_radiotap (the user's idea: grab the data earlier
# / from the larger buffer and hand it on full).
#
# wl_monitor_radiotap gets both the (truncated) sk_buff p AND the wl_rxsts sts.
# sts->pktlength (offset 0x24) is the REAL frame length "minus bcm phy hdr",
# independent of p->len. If for EAPOL sts->pktlength > p->len AND the bytes in
# p's buffer past offset 90 are real EAPOL (not zero padding), then the full
# frame is present and we can simply copy sts->pktlength instead of p->len.
#
# This probe smuggles, via the radiotap TSF field, for EAPOL frames:
#   tsf_l = 0x4c4f5045 marker
#   tsf_h = (p->len & 0xffff) | (sts->pktlength << 16)
# and additionally writes 4 probe bytes from p->data[90..93] into the radiotap
# data_rate/chan fields so the kernel can see if there is real data past the cut.
#
# Idempotent. Usage: bcm4358-monitor-eapol-probe.sh <monitormode.c>
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
    /* NEXMON-EAPOL-PROBE: report sts->pktlength vs p->len and 4 bytes past the
     * cut, for EAPOL frames, via the radiotap header (read by the kernel). */
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
            unsigned int _plen = *(volatile unsigned int *)
                                     (((unsigned char *) sts) + 0x24); /* pktlength */
            frame->tsf.tsf_l = 0x4c4f5045u;
            frame->tsf.tsf_h = ((unsigned int) p->len & 0xffff)
                             | ((_plen & 0xffff) << 16);
            /* 4 bytes at p->data[90..93] -> data_rate + chan_freq fields so the
             * kernel can tell real-data vs zero-pad past the 90-byte cut. */
            frame->data_rate = pd[90];
            frame->chan_freq = (unsigned short) (pd[91] | (pd[92] << 8));
            frame->chan_flags = pd[93];
        }
    }
'''

anchor = "frame->dbm_antnoise = sts->noise;"
if anchor not in src:
    print("::warning::eapol-probe: anchor not found; monitormode.c changed, skipping")
    sys.exit(0)

src = src.replace(anchor, anchor + "\n" + probe, 1)
open(path, "w").write(src)
print("eapol-probe: inserted NEXMON-EAPOL probe (sts->pktlength + post-cut bytes)")
PY
