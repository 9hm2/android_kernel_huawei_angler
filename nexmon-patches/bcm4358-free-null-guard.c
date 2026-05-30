/***************************************************************************
 *                                                                         *
 * NexMon BCM4358 7.112.300.14 — heap free() NULL guard                    *
 *                                                                         *
 * Root cause (found by reverse engineering the RAM firmware blob):        *
 *                                                                         *
 *   The firmware heap free() at 0x18234c dereferences the chunk header    *
 *   before the user pointer without checking for NULL:                    *
 *                                                                         *
 *       0x18234c  push {r3,r4,r5,lr}                                       *
 *       0x18234e  ldr  r3,[pc,#0x64]                                       *
 *       0x182350  mov  r5,r0                                              *
 *       0x182352  ldr  r2,[r0,#-0x8]   <-- traps when r0 == NULL          *
 *                                                                         *
 *   Under a sustained besside-ng style load (continuous inject + channel  *
 *   hopping + capture) an RX/event path (caller around 0x1d6d7c) hands a  *
 *   NULL buffer to free(), so [r0,#-8] reads 0xFFFFFFF8 and the dongle    *
 *   traps:  Dongle trap type 0x4 @ epc 0x182352 (r0 = 0).                 *
 *                                                                         *
 *   0x18234c lives in the downloaded RAM firmware (RAMSTART 0x180000), so *
 *   it can be hooked directly with a branch in the patch code region; no  *
 *   ROM flashpatch config slot is required. free() is called from 12      *
 *   sites, so guarding its entry fixes them all.                          *
 *                                                                         *
 * This is the free()-side counterpart to the pkt_buf_get_skb() NULL check *
 * (the alloc side) that fixed the 0x216dfc injection-flood trap.          *
 *                                                                         *
 **************************************************************************/

#pragma NEXMON targetregion "patch"

#include <firmware_version.h>
#include <patcher.h>
#include <wrapper.h>

/* We replace the first instruction at 0x18234c (a 2-byte
 * "push {r3,r4,r5,lr}") with a branch to our handler. nexmon emits a 4-byte
 * b.w there, which also clobbers the following "ldr r3,[pc,#0x64]" at
 * 0x18234e. The original prologue was:
 *
 *     0x18234c  push {r3,r4,r5,lr}
 *     0x18234e  ldr  r3,[pc,#0x64]   ; r3 = *0x1823b4 = 0x1806ac (heap stats)
 *     0x182350  mov  r5,r0
 *     0x182352  ldr  r2,[r0,#-8]     ; first deref (trap site)
 *
 * so the tail that runs the original free() must re-execute the push AND
 * reload r3, then resume at 0x182352. The ldr is PC-relative, so we reload
 * the SAME constant (0x1806ac) with a PC-independent movw/movt and branch to
 * 0x182352 directly. (mov r5,r0 at 0x182350 also runs naturally because we
 * resume past it via the original code only if needed; r5 is set below too.)
 */
__attribute__((at(0x18234C, "", CHIP_VER_BCM4358, FW_VER_7_112_300_14)))
void b_pkt_buf_free(void);

__attribute__((naked))
void
pkt_buf_free_orig(void *p)
{
    asm(
        "push {r3,r4,r5,lr}\n"      /* re-run original 0x18234c              */
        "movw r3, #0x06ac\n"        /* reload r3 = 0x1806ac (heap stats),    */
        "movt r3, #0x0018\n"        /*   PC-independent (was ldr [pc,#0x64]) */
        "mov  r5, r0\n"             /* re-run original 0x182350 (mov r5,r0)  */
        "movw r2, #0x2353\n"        /* resume at 0x182352 | Thumb bit,       */
        "movt r2, #0x0018\n"        /*   via movw/movt (no literal pool)     */
        "bx   r2\n"
    );
}

/* Real handler: drop NULL frees (the firmware bug), otherwise run free().
 * p arrives in r0 (AAPCS) which is the freed pointer the original free reads.
 */
__attribute__((optimize("O0")))
void
_pkt_buf_free(void *p)
{
    if (p == 0) {
        return;
    }
    pkt_buf_free_orig(p);
}

__attribute__((naked)) void
b_pkt_buf_free(void) { asm("b _pkt_buf_free\n"); }
