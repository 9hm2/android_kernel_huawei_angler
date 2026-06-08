#!/usr/bin/env bash
# Inject the FULL-BODY foreign-plaintext (EAPOL) capture HookPatch into nexmon's
# bcm4358 monitormode.c. Pairs with the d11 ucode kick (bcm4358-ucode-fullrx-fix.sh)
# that streams the full body of unprotected foreign DATA frames into the host RX
# lbuf. The ARM path wlc_recvdata drops those frames at 0x1a6cfc/0x1a6d00
# (tst.w r3,#0x310 ; bne -> drop) BEFORE the monitor dispatch, because the copy
# engine left RxStatus1 bits in 0x310 set. This HookPatch at 0x1a6cfc clones the
# full lbuf to the monitor interface via the firmware's own wlc_monitor() before
# the drop runs, so the complete EAPOL (with Key MIC) is captured. The original
# tst/bne still drops the frame from the normal host RX path.
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
// FULL-BODY FOREIGN PLAINTEXT (EAPOL) CAPTURE HOOK
//
// Pairs with the d11 ucode "kick" (spr260=0x7) that streams the full body of
// unprotected foreign DATA frames into the host RX lbuf. wlc_recvdata (RAM
// 0x1a6c84) drops these frames *before* the monitor dispatch (0x1a6d20), at:
//     0x1a6cfa  ldrh r3,[r6,#4]      ; r6 = rxhdr, [r6+4] = RxStatus1
//     0x1a6cfc  tst.w r3,#0x310      ; decrypt/seckindx status bits
//     0x1a6d00  bne.w 0x1a6e7a       ; -> DROP (skips monitor dispatch)
// The ucode copy engine leaves RxStatus1 bits in 0x310 set, so the streamed
// plaintext frame is dropped before wlc_monitor can clone it. We HookPatch the
// 4-byte tst at 0x1a6cfc: if monitor mode is on and this DATA frame is about to
// be dropped by the 0x310 test, clone the full lbuf via the firmware's own
// wlc_monitor() (p->len already = full streamed length, set at 0x1a6caa). The
// original tst/bne then still drops the frame from the normal data path.
// Live regs at the hook: r4=wlc, r5=p (lbuf), r6=rxhdr. HookPatch4 saves r0-r3,lr.

extern void *wlc_monitor(void *wlc, void *wrxh, void *p, int wlc_if);

void
wlc_recvdata_fullbody_monitor(struct wlc_info *wlc, unsigned char *rxhdr, struct sk_buff *p)
{
    unsigned short rxs1;
    unsigned char *frame;

    if (!wlc->monitor)
        return;
    rxs1 = *(unsigned short *)(rxhdr + 4);   // RxStatus1
    if (!(rxs1 & 0x310))
        return;
    frame = (unsigned char *)p->data + 6;    // 802.11 FrameControl (6-byte phy prefix)
    if ((frame[0] & 0x0c) != 0x08)           // DATA == 0x08
        return;
    wlc_monitor(wlc, rxhdr, p, 0);
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
print("fullbody-capture: injected wlc_recvdata HookPatch into", path)
PY
