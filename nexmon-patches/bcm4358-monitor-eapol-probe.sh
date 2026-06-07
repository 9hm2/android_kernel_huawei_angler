#!/usr/bin/env bash
# bcm4358-monitor-eapol-probe.sh — instrument nexmon's wl_monitor_radiotap to
# print p->len (and a few bytes past it) for EAPOL frames, so we can tell
# whether the EAPOL packet handed to the monitor tap is genuinely only ~96
# bytes (the data is gone upstream) or longer with just p->len short.
#
# This is the decisive measurement the static analysis could not give: the
# output frame size is p->len + radiotap header, and the memcpy copies exactly
# p->len-6 bytes. If p->len is 96 for EAPOL, the truncation happened before
# this function and we must fix the upstream copy; if the buffer past offset 96
# still holds real EAPOL bytes, we can simply lengthen p here.
#
# Inserts the probe right before the memcpy in wl_monitor_radiotap. Idempotent.
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
import sys, re
path = sys.argv[1]
src = open(path).read()

# The probe: for an EAPOL frame (SNAP aa aa 03 00 00 00 88 8e somewhere in the
# first 64 bytes of p->data), print p->len and 24 bytes starting at offset 88
# (just before/after the 96 boundary) so we can see if real EAPOL bytes exist
# past the cut or it is zero-padding.
probe = r'''
    /* NEXMON-EAPOL-PROBE: dump p->len + bytes around the 96 boundary for EAPOL */
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
            printf("NEXMON-EAPOL: p->len=%d snap@%d "
                   "@88:%02x%02x%02x%02x%02x%02x%02x%02x "
                   "@96:%02x%02x%02x%02x%02x%02x%02x%02x\n",
                   (int) p->len, _eo,
                   pd[88],pd[89],pd[90],pd[91],pd[92],pd[93],pd[94],pd[95],
                   pd[96],pd[97],pd[98],pd[99],pd[100],pd[101],pd[102],pd[103]);
        }
    }
'''

# Insert just before the memcpy line in wl_monitor_radiotap.
needle = "memcpy(p_new->data + sizeof(struct nexmon_radiotap_header), p->data + 6, p->len - 6);"
if needle not in src:
    print("::warning::eapol-probe: memcpy anchor not found; monitormode.c changed, skipping")
    sys.exit(0)

src = src.replace(needle, probe.strip() + "\n\n    " + needle, 1)
open(path, "w").write(src)
print("eapol-probe: inserted NEXMON-EAPOL probe before the monitor memcpy")
PY
