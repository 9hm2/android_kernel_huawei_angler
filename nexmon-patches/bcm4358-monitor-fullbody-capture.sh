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
static unsigned char g_eapol_shm[1024]  = { 0 };   // template/internal-RAM frame dump at the EAPOL moment

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

    // identify EAPOL/SNAP by aa-aa-03-00: the full LLC (aa aa 03 00 00 00 88 8e)
    // for normal frames, but only the first 4 bytes (the WEP IV aa aa 03 + keyidx
    // 00) survive a FORCE-DECRYPT (bytes 4+ incl 88 8e are XOR'd) -- so match the
    // 4-byte verbatim IV to also catch force-decrypted EAPOLs.
    for (i = 0; i + 3 < 56 && i + 3 < plen; i++)
        if (frame[i] == 0xaa && frame[i+1] == 0xaa && frame[i+2] == 0x03 &&
            frame[i+3] == 0x00) { is_eapol = 1; break; }

    if (is_eapol) {
        // bucket A = this frame's p->data. With the force-decrypt patch active and
        // a WEP key programmed (ioctl 0x610) for the AP, an unprotected EAPOL is
        // routed through WEP-decrypt: the body host-DMA (0CE3) fills p->data with
        // the XOR'd body BEFORE the firmware's 0x310/DECERR drop at 0x1a6cfc (which
        // is exactly where this hook sits). So p->data here holds [MAC hdr][aa aa
        // 03 00 verbatim][XOR(00 00 88 8e | 802.1X | EAPOL-Key body)]. Read via cmd
        // 0x601 and XOR-back on the host with RC4(aa aa 03 || wepkey) to recover
        // the plaintext Nonce+MIC.
        if (g_diagA_n < 0xffff) g_diagA_n++;
        diag_fill(g_eapol_diag, g_diagA_n, rxhdr, frame, plen);
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

///////////////////////////////////////////////////////////////////////////////
// FORCE-DECRYPT key-table programming (called from ioctl 0x610).
// Programs a per-station descriptor (stored TA = the foreign AP's A2), algo=WEP1/
// keyidx=0, and a fixed WEP key into key slot 0 -- so the force-decrypt ucode patch
// (0B1E reroute, `je r33,0x0`) routes the AP's unprotected EAPOL through WEP-decrypt.
// The fixed key below is what the host XORs back with (RC4(aa aa 03 || key)).
//
// CRASH FIX (was: ioctl 0x610 -> wlan0 ENODEV / d11 trap). Two bugs were fixed:
//  (1) The d11 MAC was RUNNING during the SHM/table writes. Broadcom requires the
//      MAC suspended (MCTL_EN_MAC cleared + core forced awake) before any SHM/AMT/
//      descriptor write; touching them under a live RXE traps the PSM -> ENODEV.
//      We now bracket ALL writes in wlc_suspend_mac_and_wait()/wlc_enable_mac()
//      (bcm4358 @0x3085C/@0x29F50; both take wlc; depth-counted, the same protocol
//      the stock fw uses around every key/SHM update).
//  (2) The old raw AMT IHR pokes (AMT_Table_Addr=(idx<<2)|w ...) used the wrong AC
//      AMT write protocol and were a second crash/RXE-wedge vector. They are DROPPED.
//      Slot 0 is used to match the shipped ucode `je r33,0x0`: an unmatched
//      unprotected frame yields AMT match index 0, so the ucode descriptor lookup
//      (0B27/0B28: spr065 = 0x334 + match_index) reads descriptor slot 0 -- and the
//      stored-TA compare (0B71/0B72: frame Addr2 vs descriptor [0x02/0x03,off5])
//      then restricts the force-decrypt to THIS AP's A2 by frame content, so slot 0
//      does NOT force-decrypt every frame.  No AMT register write is needed.
//
// Also: fd_shm_w now uses byte-precise wlc_bmac_write_objmem_byte. The previous
// wlc_bmac_write_objmem32 masks the byte offset to an 8-byte boundary and only ever
// writes the LOW 32 bits of the qword, so it both clobbered the adjacent SHM word
// AND mis-targeted odd words (e.g. word 0x336 landed on 0x334) -- the descriptor TA
// never actually programmed. Two byte writes per 16-bit word land exactly.
extern void wlc_bmac_write_objmem_byte(struct wlc_hw_info *wlc_hw, unsigned int offset,
                                       unsigned char value, int sel);
extern void wlc_suspend_mac_and_wait(struct wlc_info *wlc);   // bcm4358 @0x3085C
extern void wlc_enable_mac(struct wlc_info *wlc);             // bcm4358 @0x29F50

static const unsigned char g_fd_wepkey[13] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d
};
unsigned char *nexmon_fd_wepkey_ptr(void) { return (unsigned char *) g_fd_wepkey; }

// byte-precise SHM word write/read (SHM word W <-> byte offset W*2, LE16).
static void fd_shm_w(struct wlc_hw_info *hw, unsigned int word, unsigned short v)
{
    wlc_bmac_write_objmem_byte(hw, word * 2,     (unsigned char)(v & 0xff), 0x10000);
    wlc_bmac_write_objmem_byte(hw, word * 2 + 1, (unsigned char)(v >> 8),   0x10000);
}
static unsigned short fd_shm_r(struct wlc_hw_info *hw, unsigned int word)
{ return wlc_bmac_read_objmem_byte(hw, word * 2, 0x10000)
       | (wlc_bmac_read_objmem_byte(hw, word * 2 + 1, 0x10000) << 8); }

// Default target AP A2 (the test network's BSSID). If the caller passes a
// non-zero 6-byte MAC it is used; otherwise this hardcoded default is programmed
// (the ucmread tool cannot pass a full MAC, so `ucmread wlan0 0 8 0x610` uses it).
static const unsigned char g_fd_apmac[6] = { 0x1a, 0x26, 0x54, 0x05, 0x2f, 0x73 };

// programming read-back result (read via ioctl 0x611). bit0=desc TA hi, bit1=desc
// TA lo, bit2=keyidx/algo, bit3=key word0, bit4=nrrxtrans; 0x1F=all OK, 0xFFFF=not run.
static volatile unsigned short g_fd_verify = 0xffff;
unsigned short nexmon_fd_verify(void) { return g_fd_verify; }

void nexmon_forcedecrypt_program(struct wlc_info *wlc, const unsigned char *mac)
{
    struct wlc_hw_info *hw = wlc->hw;
    const unsigned int idx = 0;            // slot 0: matches the ucode `je r33,0x0`
    unsigned short a2w[3];
    unsigned int ktp;
    unsigned short v;
    int w;
    if (!mac || ((mac[0] | mac[2] | mac[3]) == 0)) mac = g_fd_apmac;
    a2w[0] = mac[0] | (mac[1] << 8);
    a2w[1] = mac[2] | (mac[3] << 8);
    a2w[2] = mac[4] | (mac[5] << 8);

    // ===== enter the suspend window: RXE stopped, core forced awake (crash fix) =====
    wlc_suspend_mac_and_wait(wlc);

    // per-station-descriptor scan count must cover our slot
    if (fd_shm_r(hw, 0x03E) <= idx) fd_shm_w(hw, 0x03E, idx + 1);
    // per-station descriptor: validate word0 (bit3=0), stored TA = A2 (0B71/0B72 gate)
    fd_shm_w(hw, 0x334 + idx + 0x00, 0x0000);
    fd_shm_w(hw, 0x334 + idx + 0x02, a2w[0]);
    fd_shm_w(hw, 0x334 + idx + 0x03, a2w[1]);
    // keyidx/algo word: algo=WEP1(1), keyidx=0
    fd_shm_w(hw, 0x2F0 + idx, 0x0001);
    // key material into KTP key slot 0 (8 words = 16 bytes; key repeated to fill)
    ktp = fd_shm_r(hw, 0x2B);
    for (w = 0; w < 8; w++)
        fd_shm_w(hw, ktp + w,
                 (unsigned short)(g_fd_wepkey[(2 * w) % 13] | (g_fd_wepkey[(2 * w + 1) % 13] << 8)));

    // read-back verification (still inside the suspend window; SHM quiescent)
    g_fd_verify = 0;
    if (fd_shm_r(hw, 0x334 + idx + 0x02) == a2w[0]) g_fd_verify |= 1 << 0;
    if (fd_shm_r(hw, 0x334 + idx + 0x03) == a2w[1]) g_fd_verify |= 1 << 1;
    if (fd_shm_r(hw, 0x2F0 + idx) == 0x0001)        g_fd_verify |= 1 << 2;
    v = (unsigned short)(g_fd_wepkey[0] | (g_fd_wepkey[1] << 8));
    if (fd_shm_r(hw, ktp + 0) == v)                 g_fd_verify |= 1 << 3;
    if (fd_shm_r(hw, 0x03E) > idx)                  g_fd_verify |= 1 << 4;

    // ===== leave the suspend window: MAC running again =====
    wlc_enable_mac(wlc);
}

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
