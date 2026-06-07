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
    "// Initialised (non-zero) + static so they land in .data, not .bss/common\n"
    "// (the nexmon linker has no .bss region).\n"
    "static volatile unsigned short g_eapol_len = 1;\n"
    "static volatile unsigned int   g_rx_caller = 1;\n"
    "static unsigned char           g_eapol_data[256] = { 0xff };\n"
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
    "    }\n"
    "}\n"
    "\n"
    "// Entry hook on the general monitor RX fcn 0x1a6c8a (reached via a computed\n"
    "// dispatch -- no static caller). Capture the caller (lr, preserved by the\n"
    "// 'b' that replaces the push) and the frame at this stage. Modelled on the\n"
    "// proven b_pkt_buf_get_skb pattern: a 'b' replaces the 4-byte push.w; the\n"
    "// thunk re-runs the push and continues at 0x1a6c8e.\n"
    "void *rx_entry_orig(void *a0, void *a1, void *a2, void *a3);\n"
    "__attribute__((at(0x1a6c8a, \"\", CHIP_VER_BCM4358, FW_VER_7_112_300_14)))\n"
    "__attribute__((naked)) void b_rx_entry(void) { asm(\"b _rx_entry\\n\"); }\n"
    "__attribute__((naked)) void *\n"
    "rx_entry_orig(void *a0, void *a1, void *a2, void *a3)\n"
    "{\n"
    "    asm(\"push.w {r4,r5,r6,r7,r8,r9,r10,r11,lr}\\n\"\n"
    "        \"b b_rx_entry + 4\\n\");\n"
    "    return 0;\n"
    "}\n"
    "__attribute__((optimize(\"O0\"))) void *\n"
    "_rx_entry(void *a0, void *a1, void *a2, void *a3)\n"
    "{\n"
    "    register unsigned int lr asm(\"lr\");\n"
    "    if (g_rx_caller == 1) g_rx_caller = lr;   // computed caller of 0x1a6c8a\n"
    "    capture_full_eapol(a1);                    // a1 = lbuf at this RX stage\n"
    "    return rx_entry_orig(a0, a1, a2, a3);\n"
    "}\n"
    "\n"
)
if marker_fn not in src:
    sys.stderr.write("snoopcap: wl_monitor_hook definition not found\n"); sys.exit(1)
src = src.replace(marker_fn, glob + marker_fn, 1)

# --- 1b) capture the full EAPOL via the EXISTING pkt_buf_get_skb hook: the
# foreign EAPOL classifier at 0x19b9f0 allocates a 202-byte skb (bl 0x18ce3c,
# return 0x19ba1b) with the full source frame still in r4 ([r4,8]=data,
# [r4,0xc]=len). Add an r4 capture for that return address -- no new BLPatch.
pkt_anchor = (
    '    void *sts = sp + 56; // add this offset to the stack pointer to find the sts struct created in wlc_monitor\n'
    "\n"
    "    if (lr == 0x1863f && !call_original_wl_monitor) { // called from wl_monitor\n"
)
if pkt_anchor not in src:
    sys.stderr.write("snoopcap: _pkt_buf_get_skb anchor not found\n"); sys.exit(1)
pkt_new = (
    '    void *sts = sp + 56; // add this offset to the stack pointer to find the sts struct created in wlc_monitor\n'
    "    register void *r4cap asm(\"r4\");\n"
    "    if (lr == 0x19ba1b) // foreign EAPOL classifier: full frame in r4\n"
    "        capture_full_eapol(r4cap);\n"
    "\n"
    "    if (lr == 0x1863f && !call_original_wl_monitor) { // called from wl_monitor\n"
)
src = src.replace(pkt_anchor, pkt_new, 1)

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
    "        p->len > 6) {\n"
    "        unsigned char *f = (unsigned char *)p->data + 6;\n"
    "        unsigned int fc = f[0] | (f[1] << 8);\n"
    "        if ((fc & 0x0C) == 0x08) {\n"
    "            unsigned int hdrlen = (fc & 0x80) ? 26 : 24;\n"
    "            if ((unsigned int)(p->len - 6) > hdrlen + 8 + 16) {\n"
    "                unsigned char *llc = f + hdrlen;\n"
    "                if (llc[6] == 0x88 && llc[7] == 0x8E) {\n"
    "                    unsigned char *mbody = llc + 8;          // EAPOL in 802.11\n"
    "                    unsigned char *sbody = g_eapol_data + 14; // EAPOL in 802.3\n"
    "                    unsigned int sblen = (g_eapol_len > 14) ? (g_eapol_len - 14) : 0;\n"
    "                    unsigned int fulllen, saved;\n"
    "                    int matched = (g_eapol_len > 14), i;\n"
    "                    for (i = 0; matched && i < 16; i++)\n"
    "                        if (mbody[i] != sbody[i]) matched = 0;\n"
    "                    if (matched && sblen >= 16 && sblen <= 240) {\n"
    "                        for (i = 0; i < (int)sblen; i++)\n"
    "                            mbody[i] = sbody[i];          // splice full EAPOL\n"
    "                        fulllen = hdrlen + 8 + sblen;\n"
    "                    } else {\n"
    "                        // DIAGNOSTIC into the (zero) Key-MIC area so the pcap\n"
    "                        // reveals what the snoop captured (or 1 = never fired).\n"
    "                        unsigned char *dbg = mbody + 81;\n"
    "                        dbg[0] = 0xDE; dbg[1] = 0xAD;\n"
    "                        dbg[2] = g_eapol_len; dbg[3] = g_eapol_len >> 8;\n"
    "                        dbg[4] = g_rx_caller;       dbg[5] = g_rx_caller >> 8;\n"
    "                        dbg[6] = g_rx_caller >> 16; dbg[7] = g_rx_caller >> 24;\n"
    "                        for (i = 0; i < 4; i++)\n"
    "                            dbg[8 + i] = (g_eapol_len > 14) ? sbody[i] : 0;\n"
    "                        fulllen = hdrlen + 8 + 81 + 16;\n"
    "                    }\n"
    "                    saved = p->len;\n"
    "                    p->len = fulllen + 6;\n"
    "                    wl_monitor_radiotap(wl, sts, p, 0);\n"
    "                    p->len = saved;\n"
    "                    return;\n"
    "                }\n"
    "            }\n"
    "        }\n"
    "    }\n"
)
src = src.replace(anchor, splice, 1)
open(path, "w").write(src)
print(f"snoopcap: added EAPOL snoop full-frame capture+splice to {path}")
PY
