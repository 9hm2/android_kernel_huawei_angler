#!/usr/bin/env bash
# DIAGNOSTIC probe (temporary): determine whether the full foreign EAPOL frame
# -- specifically the Key MIC, which the monitor copy delivers as zeros -- is
# reachable in firmware RAM from the monitor packet `p`, e.g. via a chained
# lbuf (p->next). Results are encoded INTO the captured monitor frame (the
# firmware console is not readable here), at the EAPOL Key-MIC offset, which is
# zero anyway -- so they show up directly in the pcap.
#
# lbuf layout (from ROM wl_monitor 0x18628): +0x00 next, +0x08 data, +0x0C len.
#
# At frame offset (hdrlen + 89) -- the 16-byte Key MIC, currently all zeros --
# we write a 32-byte diagnostic block:
#   [0:2]   0xDE 0xAD            marker to locate the block
#   [2:6]   p->next              (0 => not chained)
#   [6:8]   p->len (original)
#   [8:10]  p->next->len         (if next != 0)
#   [10:26] first 16 bytes of p->next->data   (if next != 0; the continuation,
#                                               i.e. the bytes after p's data)
#   [26:28] 0x0001 if next!=0 else 0x0000
# p->len is then set so the clone copies through the diagnostic block.
#
# Interpretation from the pcap:
#   next != 0 and bytes[10:26] look like the EAPOL continuation (IV/RSC/MIC)
#     => the full frame IS reachable; the real fix follows the chain.
#   next == 0 (and the deep-buffer bytes are zero/stale)
#     => the firmware does not retain the full foreign EAPOL payload in RAM;
#        the MIC cannot be recovered passively on this chip.
#
# Usage: bcm4358-monitor-eapol-probe.sh <path-to-monitormode.c>
set -euo pipefail

SRC="${1:?usage: $0 <monitormode.c>}"
[ -f "$SRC" ] || { echo "::warning::eapol-probe: $SRC not found, skipping"; exit 0; }
if grep -q "EAPOL MIC-reachability probe" "$SRC"; then
	echo "eapol-probe already present in $SRC, nothing to do"; exit 0
fi

python3 - "$SRC" <<'PY'
import sys
path = sys.argv[1]
src = open(path).read()

anchor = "wl_monitor_hook(struct wl_info *wl, struct wl_rxsts *sts, struct sk_buff *p) {\n"
if anchor not in src:
    sys.stderr.write("eapol-probe: wl_monitor_hook anchor not found\n"); sys.exit(1)

probe = anchor + (
    "    // EAPOL MIC-reachability probe (diagnostic): encode lbuf chain info\n"
    "    // into the (zero) Key-MIC field so it is visible in the captured pcap.\n"
    "    if (p->len > 6) {\n"
    "        unsigned char *f = (unsigned char *)p->data + 6;\n"
    "        unsigned int fc = f[0] | (f[1] << 8);\n"
    "        if ((fc & 0x0C) == 0x08) {\n"
    "            unsigned int hdrlen = (fc & 0x80) ? 26 : 24;\n"
    "            if ((unsigned int)(p->len - 6) > hdrlen + 12) {\n"
    "                unsigned char *llc = f + hdrlen;\n"
    "                if (llc[6] == 0x88 && llc[7] == 0x8E) {\n"
    "                    unsigned int nextp = *(volatile unsigned int *)((unsigned char *)p + 0);\n"
    "                    unsigned char *o = f + hdrlen + 89; // Key MIC offset\n"
    "                    int i;\n"
    "                    o[0] = 0xDE; o[1] = 0xAD;\n"
    "                    o[2] = nextp; o[3] = nextp >> 8;\n"
    "                    o[4] = nextp >> 16; o[5] = nextp >> 24;\n"
    "                    o[6] = p->len; o[7] = p->len >> 8;\n"
    "                    if (nextp) {\n"
    "                        unsigned int ndata = *(volatile unsigned int *)(nextp + 8);\n"
    "                        unsigned int nlen  = *(volatile unsigned short *)(nextp + 0xC);\n"
    "                        o[8] = nlen; o[9] = nlen >> 8;\n"
    "                        for (i = 0; i < 16; i++)\n"
    "                            o[10 + i] = ((unsigned char *)ndata)[i];\n"
    "                        o[26] = 1; o[27] = 0;\n"
    "                    } else {\n"
    "                        // not chained: sample deep in p's own buffer\n"
    "                        for (i = 0; i < 16; i++)\n"
    "                            o[10 + i] = f[hdrlen + 89 + 32 + i];\n"
    "                        o[26] = 0; o[27] = 0;\n"
    "                    }\n"
    "                    if ((unsigned int)(6 + hdrlen + 89 + 28) > p->len)\n"
    "                        p->len = 6 + hdrlen + 89 + 28;\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
)
src = src.replace(anchor, probe, 1)
open(path, "w").write(src)
print(f"eapol-probe: added EAPOL MIC-reachability probe to {path}")
PY
