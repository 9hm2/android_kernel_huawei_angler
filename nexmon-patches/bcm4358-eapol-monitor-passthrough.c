/***************************************************************************
 *                                                                         *
 * NexMon BCM4358 7.112.300.14 — monitor-gated EAPOL passthrough           *
 *                                                                         *
 * Fixes the monitor-mode EAPOL truncation (see                            *
 * nexmon-patches/EAPOL-TRUNCATION-RE.md): captured WPA2 EAPOL-Key frames   *
 * are cut to a fixed 90 on-air bytes, dropping the M2 MIC and M3 GTK, so   *
 * the handshake is uncrackable. On-device probes proved the cut is        *
 * EAPOL-specific (encrypted data reaches the monitor full to 1904B) and    *
 * happens because the fullmac firmware intercepts 802.1X/EAPOL on RX and    *
 * stages it into a small fixed (~96B) host-event buffer, which is the      *
 * truncated copy the monitor path then clones.                            *
 *                                                                         *
 * Root mechanism, found by RE of the RAM blob:                            *
 *                                                                         *
 *   RX handler 0x1a560c calls the EAPOL forwarder 0x19ace8, which does:    *
 *     0x19ad02  ldr  r2,[pc,#0x4c]   ; r2 = 0xffff888e (EAPOL ethertype)   *
 *     0x19ad04  sxth r3,r3           ; r3 = sign-extended frame ethertype  *
 *     0x19ad06  cmp  r3,r2           ; is this frame EAPOL?                *
 *     0x19ad08  bne  0x19ad1e        ; no  -> normal (full) data path      *
 *     0x19ad0a  ...  bl 0x19a4d8     ; yes -> parse + ...                  *
 *     0x19ad1a  bl   0x47504         ;        host-event staging (the 96B) *
 *     0x19ad1e  ...                  ; (rejoin)                            *
 *                                                                         *
 *   wlc is arg0 of 0x19ace8 (saved into r6 at entry), and per the nexmon   *
 *   BCM4358 structs, wlc->monitor is at offset 0x208.                      *
 *                                                                         *
 * Fix: hook the cmp/bne at 0x19ad06. When monitor mode is active           *
 * (wlc->monitor != 0) force the "not EAPOL" branch to 0x19ad1e, so the     *
 * EAPOL is NOT intercepted and flows through the same full data path as    *
 * every other frame -> the monitor clone is full length and crackable.     *
 * When monitor is OFF the original cmp/bne runs unchanged, so the phone's   *
 * own WPA supplicant still gets its EAPOL via the firmware as normal.       *
 *                                                                         *
 * 0x19ad06 lives in the downloaded RAM firmware (RAMSTART 0x180000), so it  *
 * is hooked directly with a 4-byte branch in the patch code region; no ROM *
 * flashpatch config slot is required.                                     *
 *                                                                         *
 **************************************************************************/

#pragma NEXMON targetregion "patch"

#include <firmware_version.h>
#include <patcher.h>
#include <wrapper.h>

/* Replace the 4 bytes at 0x19ad06 (cmp r3,r2 ; bne 0x19ad1e) with a 4-byte
 * b.w to our gate. The gate re-implements the original test and adds the
 * monitor-mode override, then resumes at one of the two original targets.
 */
__attribute__((at(0x19AD06, "", CHIP_VER_BCM4358, FW_VER_7_112_300_14)))
void b_eapol_monitor_gate(void);

__attribute__((naked))
void
eapol_monitor_gate(void)
{
    asm(
        /* r6 = wlc (set at 0x19acea), r3 = frame ethertype (sxth),         */
        /* r2 = 0xffff888e. ip (r12) is a free scratch register here.       */
        "ldr  ip, [r6, #0x208]\n"   /* wlc->monitor                         */
        "cmp  ip, #0\n"
        "bne  1f\n"                 /* monitor active -> skip EAPOL intercept */
        "cmp  r3, r2\n"             /* original: frame ethertype == EAPOL?  */
        "bne  1f\n"                 /* not EAPOL -> skip                    */
        /* EAPOL and not monitor: resume original processing at 0x19ad0a.   */
        "movw ip, #0xad0b\n"        /* 0x19ad0a | Thumb bit                 */
        "movt ip, #0x0019\n"
        "bx   ip\n"
        "1:\n"                      /* skip path: resume at 0x19ad1e        */
        "movw ip, #0xad1f\n"        /* 0x19ad1e | Thumb bit                 */
        "movt ip, #0x0019\n"
        "bx   ip\n"
    );
}

__attribute__((naked)) void
b_eapol_monitor_gate(void) { asm("b eapol_monitor_gate\n"); }
