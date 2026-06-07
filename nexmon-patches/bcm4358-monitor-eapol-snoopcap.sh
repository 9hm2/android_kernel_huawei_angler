#!/usr/bin/env bash
# Full passive EAPOL capture via the firmware's EAPOL SNOOP input.
#
# Proven facts:
#  - The monitor clone only holds ~86 bytes (802.11 hdr + LLC + EAPOL through the
#    nonce); the Key MIC / key-data past that is zero -> not crackable.
#  - The firmware's EAPOL snoop (ROM 0x23d68, called from RAM 0x1a3372 inside the
#    RX classifier) is handed the WHOLE frame: it copies [pkt+0x0c]-14 bytes from
#    [pkt+0x08]+14, i.e. a full 802.3 (ethernet+EAPOL) frame WITH the MIC.
#
# Strategy (no gate bypass, no risky pointer chase):
#  1. Redirect the BL at 0x1a3372 to a hook that COPIES that full 802.3 EAPOL
#     frame into a static buffer, then tail-calls the original snoop unchanged.
#  2. In wl_monitor_hook(), when the truncated monitor EAPOL frame arrives, match
#     it to the stashed full frame by the EAPOL body head (both share the first
#     ~16 body bytes), splice the full body into the 802.11 frame, clone it at
#     full length, and RESTORE p->len (so the shared RX packet is untouched for
#     the snoop/association path -> no dongle trap).
#
# Matching makes it safe: if the stash is stale or the formats do not line up,
# nothing is spliced (no corruption, no crash). Only adds bytes that are present.
#
# Usage: bcm4358-monitor-eapol-snoopcap.sh <path-to-monitormode.c>
set -euo pipefail
SRC="${1:?usage: $0 <monitormode.c>}"
[ -f "$SRC" ] || { echo "::warning::snoopcap: $SRC not found, skipping"; exit 0; }
if grep -q "EAPOL snoop full-frame capture" "$SRC"; then
	echo "snoopcap already present in $SRC, nothing to do"; exit 0
fi

python3 - "$SRC" <<'PY'
import sys
path = sys.argv[1]
src = open(path).read()

# --- 1) globals + capture + snoop-call hook + BLPatch, inserted before wl_monitor_hook
marker_fn = "void\nwl_monitor_hook("
glob = (
    "// EAPOL snoop full-frame capture: stash of the complete 802.3 EAPOL frame\n"
    "// (ethernet header + EAPOL incl. MIC) the firmware passes to its snoop.\n"
    "volatile unsigned int   g_eapol_seq = 0;\n"
    "volatile unsigned short g_eapol_len = 0;\n"
    "unsigned char           g_eapol_data[400];\n"
    "\n"
    "void\n"
    "capture_full_eapol(void *pkt)\n"
    "{\n"
    "    unsigned char *p = (unsigned char *)pkt;\n"
    "    unsigned char *data = *(unsigned char **)(p + 0x08);\n"
    "    unsigned int   len  = *(unsigned short *)(p + 0x0C);\n"
    "    unsigned int   i;\n"
    "    if (len >= 38 && len <= sizeof(g_eapol_data)) {\n"
    "        for (i = 0; i < len; i++)\n"
    "            g_eapol_data[i] = data[i];\n"
    "        g_eapol_len = (unsigned short)len;\n"
    "        g_eapol_seq++;\n"
    "    }\n"
    "}\n"
    "\n"
    "// Hooked in place of `bl 0x23d68` at 0x1a3372. Same args as the snoop\n"
    "// (r0..r3 + one stacked arg); the packet is the 2nd arg. Capture, then\n"
    "// tail-call the original snoop so firmware behaviour is unchanged.\n"
    "void\n"
    "snoop_call_hook(void *a0, void *a1, void *a2, void *a3, void *a4)\n"
    "{\n"
    "    void (*orig)(void *, void *, void *, void *, void *) =\n"
    "        (void (*)(void *, void *, void *, void *, void *))(0x23d68 | 1);\n"
    "    capture_full_eapol(a1);\n"
    "    orig(a0, a1, a2, a3, a4);\n"
    "}\n"
    "\n"
    "__attribute__((at(0x1a3372, \"\", CHIP_VER_BCM4358, FW_VER_7_112_300_14)))\n"
    "BLPatch(snoop_call_hook, snoop_call_hook);\n"
    "\n"
)
if marker_fn not in src:
    sys.stderr.write("snoopcap: wl_monitor_hook definition not found\n"); sys.exit(1)
src = src.replace(marker_fn, glob + marker_fn, 1)

# --- 2) splice into wl_monitor_hook body
anchor = "wl_monitor_hook(struct wl_info *wl, struct wl_rxsts *sts, struct sk_buff *p) {\n"
if anchor not in src:
    sys.stderr.write("snoopcap: wl_monitor_hook anchor not found\n"); sys.exit(1)
splice = anchor + (
    "    // EAPOL snoop full-frame capture: if this is a truncated EAPOL monitor\n"
    "    // frame and we just stashed the matching full 802.3 EAPOL, splice the\n"
    "    // complete body (incl. MIC) into the 802.11 frame, clone it full, and\n"
    "    // restore p->len so the shared RX packet is left intact for the snoop.\n"
    "    if ((wl->wlc->monitor & 0xFF) == MONITOR_RADIOTAP &&\n"
    "        p->len > 6 && g_eapol_len > 14) {\n"
    "        unsigned char *f = (unsigned char *)p->data + 6;\n"
    "        unsigned int fc = f[0] | (f[1] << 8);\n"
    "        if ((fc & 0x0C) == 0x08) {\n"
    "            unsigned int hdrlen = (fc & 0x80) ? 26 : 24;\n"
    "            if ((unsigned int)(p->len - 6) > hdrlen + 8 + 16) {\n"
    "                unsigned char *llc = f + hdrlen;\n"
    "                if (llc[6] == 0x88 && llc[7] == 0x8E) {\n"
    "                    unsigned char *mbody = llc + 8;          // EAPOL in 802.11\n"
    "                    unsigned char *sbody = g_eapol_data + 14; // EAPOL in 802.3\n"
    "                    unsigned int   sblen = g_eapol_len - 14;\n"
    "                    int match = 1, i;\n"
    "                    for (i = 0; i < 16; i++)\n"
    "                        if (mbody[i] != sbody[i]) { match = 0; break; }\n"
    "                    if (match && sblen >= 16 && sblen <= 300) {\n"
    "                        unsigned int saved = p->len;\n"
    "                        for (i = 0; i < (int)sblen; i++)\n"
    "                            mbody[i] = sbody[i];\n"
    "                        p->len = hdrlen + 8 + sblen + 6;\n"
    "                        wl_monitor_radiotap(wl, sts, p, 0);\n"
    "                        p->len = saved;\n"
    "                        return;\n"
    "                    }\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
)
src = src.replace(anchor, splice, 1)
open(path, "w").write(src)
print(f"snoopcap: added EAPOL snoop full-frame capture+splice to {path}")
PY
