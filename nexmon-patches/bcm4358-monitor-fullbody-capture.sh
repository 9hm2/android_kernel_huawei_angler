#!/usr/bin/env bash
# Inject the FULL-BODY foreign-plaintext (EAPOL) capture HookPatch + an on-device
# DIAGNOSTIC recorder into nexmon's bcm4358 monitormode.c.
#
# Pairs with the d11 ucode kick. The hook sits at wlc_recvdata 0x1a6cfc (where
# the firmware drops streamed plaintext DATA frames, just before the monitor
# dispatch). For every frame reaching the hook it RECORDS into g_eapol_diag (read
# back via the cmd 0x601 ioctl) the RX state, and for EAPOL frames also the frame
# bytes -- so we can see on-device whether the body streamed (p->len) and why the
# frame is/ isn't monitored. It also attempts the monitor clone (wlc_monitor).
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
// FULL-BODY FOREIGN PLAINTEXT (EAPOL) CAPTURE HOOK + DIAGNOSTIC RECORDER
//
// HookPatch at wlc_recvdata 0x1a6cfc (the streamed-plaintext drop site, just
// before the monitor dispatch at 0x1a6d20). r4=wlc, r5=p, r6=rxhdr.
//
// g_eapol_diag layout (read via ioctl cmd 0x601, offset 0..255):
//   [0..1]   total frames seen at the hook (LE16, saturating)
//   [2..3]   EAPOL (88 8e) frames seen (LE16)
//   [4..5]   clone attempts (LE16)
//   [6..7]   last EAPOL p->len (LE16)  <-- >86 means the body streamed
//   [8..9]   last EAPOL RxStatus1 (rxhdr[4..5])
//   [10..11] last EAPOL RxStatus2 (rxhdr[6..7])
//   [12..13] last EAPOL RxFrameSize (rxhdr[0..1])
//   [14]     last EAPOL wlc->monitor (low byte)
//   [15]     flags: bit0=rxs1&0x310, bit1=FCtype==DATA
//   [16..159] last EAPOL frame bytes p->data[6 .. 6+143]

static volatile unsigned short g_diag_seen   = 0;
static volatile unsigned short g_diag_eapol  = 0;
static volatile unsigned short g_diag_clones = 0;
static unsigned char           g_eapol_diag[256] = { 0xff };

extern void *wlc_monitor(void *wlc, void *wrxh, void *p, int wlc_if);

void
wlc_recvdata_fullbody_monitor(struct wlc_info *wlc, unsigned char *rxhdr, struct sk_buff *p)
{
    unsigned char *frame = (unsigned char *)p->data + 6;
    unsigned int plen = p->len;
    unsigned short rxs1 = *(unsigned short *)(rxhdr + 4);
    unsigned int i;
    int is_eapol = 0;

    if (g_diag_seen < 0xffff) g_diag_seen++;

    // identify EAPOL by the LLC/SNAP ethertype 0x888e in the first ~40 bytes
    for (i = 0; i + 1 < 40 && i + 1 < plen; i++)
        if (frame[i] == 0x88 && frame[i + 1] == 0x8e) { is_eapol = 1; break; }

    if (is_eapol) {
        if (g_diag_eapol < 0xffff) g_diag_eapol++;
        g_eapol_diag[0]  = g_diag_seen;       g_eapol_diag[1]  = g_diag_seen >> 8;
        g_eapol_diag[2]  = g_diag_eapol;      g_eapol_diag[3]  = g_diag_eapol >> 8;
        g_eapol_diag[6]  = plen;              g_eapol_diag[7]  = plen >> 8;
        g_eapol_diag[8]  = rxhdr[4];          g_eapol_diag[9]  = rxhdr[5];
        g_eapol_diag[10] = rxhdr[6];          g_eapol_diag[11] = rxhdr[7];
        g_eapol_diag[12] = rxhdr[0];          g_eapol_diag[13] = rxhdr[1];
        g_eapol_diag[14] = (unsigned char) wlc->monitor;
        g_eapol_diag[15] = ((rxs1 & 0x310) ? 1 : 0) | (((frame[0] & 0x0c) == 0x08) ? 2 : 0);
        for (i = 0; i < 144 && i < plen; i++)
            g_eapol_diag[16 + i] = frame[i];
    }

    // capture attempt: clone the full frame to monitor before the drop
    if (wlc->monitor && (rxs1 & 0x310) && (frame[0] & 0x0c) == 0x08) {
        if (g_diag_clones < 0xffff) g_diag_clones++;
        g_eapol_diag[4] = g_diag_clones; g_eapol_diag[5] = g_diag_clones >> 8;
        wlc_monitor(wlc, rxhdr, p, 0);
    }
}

unsigned char *
nexmon_eapol_diag_ptr(void) { return g_eapol_diag; }

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
print("fullbody-capture: injected wlc_recvdata HookPatch + diag recorder into", path)
PY
