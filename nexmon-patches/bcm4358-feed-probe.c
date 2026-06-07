/***************************************************************************
 * NexMon BCM4358 — measure the packet length at the RAM monitor-feed       *
 * (0x1a6d28) to decide whether the full EAPOL frame is present there.      *
 *                                                                         *
 * RE (ROM+RAM in r2) found the monitor feed in the RX receive fn 0x1a6c8a:*
 *   0x1a6c8e ldr r6,[r1,8]      ; packet data                             *
 *   0x1a6caa strh r3,[r5,0xc]   ; r5->len = full frame len (rx - phy hdr) *
 *   0x1a6d04 ldr r3,[r4,0x208]  ; wlc->monitor                            *
 *   0x1a6d28 bl  0x1ecc4        ; wlc_monitor(wlc, data, pkt=r5, flag)    *
 * The ROM wlc_monitor/wl_monitor then build the (for EAPOL: 96-byte) clone*
 * the nexmon hook sees. If r5->len here is the FULL EAPOL length, the cut  *
 * is inside ROM; if it is already 96, it is even further upstream.        *
 *                                                                         *
 * This BLPatch replaces the 4-byte `bl 0x1ecc4` at 0x1a6d28 with a bl to   *
 * our wrapper, which records pkt->len ([r5,0xc] = arg2+0xC) into a global  *
 * then branches to the original wlc_monitor at 0x1ecc4. The probe in       *
 * wl_monitor_radiotap reads the global and smuggles it to the kernel via   *
 * the radiotap TSF.                                                       *
 **************************************************************************/

#pragma NEXMON targetregion "patch"

#include <firmware_version.h>
#include <patcher.h>
#include <wrapper.h>

/* last packet length seen at the RAM monitor feed (0x1a6d28). */
volatile unsigned int nexmon_feed_len = 0;

/* Tail-call the original wlc_monitor at 0x1ecc4 (PC-independent). */
__attribute__((naked))
static void
wlc_monitor_orig(void *wlc, void *data, void *pkt, int flag)
{
    asm(
        "movw r12, #0xecc5\n"   /* 0x1ecc4 | Thumb bit */
        "movt r12, #0x0001\n"
        "bx   r12\n"
    );
}

/* Wrapper: record pkt->len (arg2 = r2 = the lbuf struct; len @ +0xC),
 * then run the original wlc_monitor. */
__attribute__((optimize("O0")))
void
wlc_monitor_feedprobe(void *wlc, void *data, void *pkt, int flag)
{
    nexmon_feed_len = *(volatile unsigned short *)
                          (((unsigned char *) pkt) + 0x0C);
    wlc_monitor_orig(wlc, data, pkt, flag);
}

/* Replace the `bl 0x1ecc4` at 0x1a6d28 with a bl to our wrapper. */
__attribute__((at(0x1A6D28, "", CHIP_VER_BCM4358, FW_VER_7_112_300_14)))
BLPatch(wlc_monitor_feedprobe, wlc_monitor_feedprobe);
