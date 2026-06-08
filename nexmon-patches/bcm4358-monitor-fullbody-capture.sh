#!/usr/bin/env bash
# Inject the FULL-BODY foreign-plaintext (EAPOL) capture DIAGNOSTIC recorder into
# nexmon's bcm4358 monitormode.c.
#
# Reliable, COMPARATIVE ground-truth measurement (replaces the broken offline
# emulator). HookPatch at wlc_recvdata 0x1a6cfc. From the binary the register/
# layout at that site is CONFIRMED:
#   r4 = wlc ; r5 = p (sk_buff) ; r6 = rxhdr (d11rxhdr start)
#   after the earlier skb_pull by wlc->[0x5e4], p->data points at the 802.11 MAC
#   header (offset 0, NOT +6 -- the +6 belongs to the later wl_monitor stage) and
#   p->len is the REAL delivered frame length. The frame the d11 DMA'd is exactly
#   p->data[0 .. p->len-1].
#
# We keep TWO buckets so the on-device report shows, side by side, the rxhdr of a
# truncated foreign EAPOL frame AND a full-length foreign DATA frame -- the rxhdr
# difference reveals the field that drives the d11 body-copy truncation.
#   bucket A (ioctl cmd 0x601): most recent EAPOL (ethertype 88 8e) frame
#   bucket B (ioctl cmd 0x602): largest DATA frame seen (a FULL delivery sample)
# Layout (256 bytes each):
#   [0..1]   match counter (LE16, saturating)
#   [2..3]   p->len (LE16)               <-- true delivered frame length
#   [4..35]  rxhdr[0..31]                <-- full d11rxhdr (RxFrameSize@0, RxStatus1@4, RxStatus2@6, ...)
#   [36..255] p->data[0..219]            <-- raw 802.11 frame from offset 0
#
# Pure measurement: we do NOT clone to monitor here (the stock nexmon wl_monitor
# path still delivers frames to airodump independently). Crash-safe: only reads,
# bounded by p->len, no pointer chasing.
#
# Usage: bcm4358-monitor-fullbody-capture.sh <monitormode.c>
set -euo pipefail
SRC="${1:?usage: $0 <monitormode.c>}"
[ -f "$SRC" ] || { echo "::warning::fullbody-capture: $SRC not found, skipping"; exit 0; }
if grep -q "FULL-BODY FOREIGN PLAINTEXT" "$SRC"; then
    echo "fullbody-capture: already present in $SRC"; exit 0
fi

python3 - "$SRC" <<'PY'
import sys
path = sys.argv[1]
src = open(path).read()

anchor = 'b_pkt_buf_get_skb(void) { asm("b _pkt_buf_get_skb\\n"); }\n'
if anchor not in src:
    sys.stderr.write("fullbody-capture: pkt_buf_get_skb anchor not found\n"); sys.exit(1)

hook = r'''
///////////////////////////////////////////////////////////////////////////////
// FULL-BODY FOREIGN PLAINTEXT (EAPOL) CAPTURE -- COMPARATIVE DIAGNOSTIC RECORDER
//
// HookPatch at wlc_recvdata 0x1a6cfc. r4=wlc, r5=p, r6=rxhdr (CONFIRMED from the
// binary). Frame = p->data (offset 0); p->len = true delivered length.
//
// Two readable buckets (ioctl cmd 0x601 = EAPOL sample, cmd 0x602 = full DATA
// sample). Identical 256-byte layout:
//   [0..1] count  [2..3] p->len  [4..35] rxhdr[0..31]  [36..255] p->data[0..219]

static volatile unsigned short g_diagA_n = 0;
static volatile unsigned short g_diagB_n = 0;
static volatile unsigned short g_diagB_maxlen = 0;
static unsigned char g_eapol_diag[256]  = { 0 };   // bucket A: EAPOL
static unsigned char g_eapol_diag2[256] = { 0 };   // bucket B: largest DATA
static unsigned char g_eapol_shm[1024]  = { 0 };   // d11 RX-buffer SRAM dump (0xC00..0xFFF)

// read live d11 SHM (objmem select 0x10000) -- the proven path; lets us correlate
// the EAPOL frame with the ucode 0B95 stamps captured at the SAME instant.
extern unsigned char wlc_bmac_read_objmem_byte(void *wlc_hw, unsigned int off, int sel);

static void
diag_fill(unsigned char *buf, unsigned short cnt,
          unsigned char *rxhdr, unsigned char *frame, unsigned int plen)
{
    unsigned int i;
    for (i = 36; i < 256; i++) buf[i] = 0;       // clear stale frame bytes
    buf[0] = cnt; buf[1] = cnt >> 8;
    buf[2] = plen; buf[3] = plen >> 8;
    for (i = 0; i < 32; i++) buf[4 + i] = rxhdr[i];
    for (i = 0; i < 220 && i < plen; i++) buf[36 + i] = frame[i];
}

void
wlc_recvdata_fullbody_monitor(struct wlc_info *wlc, unsigned char *rxhdr, struct sk_buff *p)
{
    unsigned char *frame = (unsigned char *)p->data;   // CONFIRMED: offset 0 (real 802.11 at +6)
    unsigned int plen = p->len;
    unsigned int i;
    int is_eapol = 0;
    int is_data  = ((frame[0] & 0x0c) == 0x08);        // FC type == data (note: +6 prefix present)

    // identify EAPOL by the FULL LLC/SNAP signature aa-aa-03-00-00-00-88-8e
    // (matching only 88 8e false-positives on MAC addresses ending in 88:8e)
    for (i = 0; i + 7 < 56 && i + 7 < plen; i++)
        if (frame[i] == 0xaa && frame[i+1] == 0xaa && frame[i+2] == 0x03 &&
            frame[i+3] == 0x00 && frame[i+4] == 0x00 && frame[i+5] == 0x00 &&
            frame[i+6] == 0x88 && frame[i+7] == 0x8e) { is_eapol = 1; break; }

    if (is_eapol) {
        void *wlc_hw = wlc->hw;
        if (g_diagA_n < 0xffff) g_diagA_n++;
        diag_fill(g_eapol_diag, g_diagA_n, rxhdr, frame, plen);
        // On-device scan found received frames stored FULL (incl body/MIC) in d11
        // SRAM at objmem(0x10000) ~0xC00..0xFFF. Dump that whole RX-buffer region
        // AT the EAPOL moment so we can find this EAPOL with its complete tail
        // (the WPA2 Key MIC). Read back chunked via cmd 0x606 (offset-aware).
        for (i = 0; i < 1024; i++)
            g_eapol_shm[i] = wlc_bmac_read_objmem_byte(wlc_hw, 0xC00 + i, 0x10000);
    }

    // bucket B: keep the LARGEST data frame seen (a full-delivery sample to diff)
    if (is_data && plen > g_diagB_maxlen) {
        g_diagB_maxlen = plen;
        if (g_diagB_n < 0xffff) g_diagB_n++;
        diag_fill(g_eapol_diag2, g_diagB_n, rxhdr, frame, plen);
    }
}

unsigned char *nexmon_eapol_diag_ptr(void)  { return g_eapol_diag; }
unsigned char *nexmon_eapol_diag2_ptr(void) { return g_eapol_diag2; }
unsigned char *nexmon_eapol_shm_ptr(void)   { return g_eapol_shm; }

__attribute__((naked)) void
wlc_recvdata_fullbody_monitor_trampoline(void)
{
    asm(
        "mov r0, r4\n"
        "mov r1, r6\n"
        "mov r2, r5\n"
        "b wlc_recvdata_fullbody_monitor\n"
    );
}

__attribute__((at(0x1a6cfc, "", CHIP_VER_BCM4358, FW_VER_7_112_300_14)))
HookPatch4(wlc_recvdata_fullbody, wlc_recvdata_fullbody_monitor_trampoline, "tst.w r3, #0x310");

'''
src = src.replace(anchor, anchor + hook, 1)
open(path, "w").write(src)
print("fullbody-capture: injected comparative wlc_recvdata diag (A=EAPOL,B=DATA) into", path)
PY
