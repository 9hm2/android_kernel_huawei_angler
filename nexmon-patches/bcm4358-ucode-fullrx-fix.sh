#!/usr/bin/env bash
# THE FIX v2 (static-RE'd, on-device-informed, verified): deliver the FULL
# unprotected foreign DATA frame (WPA2 EAPOL incl. Key MIC) to the host monitor on
# the BCM4358 d11 by appending the post-lookahead remainder via the d11 DAGG body
# copy (cmd=7), WITHOUT triggering the host AMSDU drop.
#
# Why the earlier fix failed (measured on-device):
#  - Setting [0x841] bit0 (RXS_AMSDU) to open the 0B95 kick gate made the host
#    de-aggregate the plaintext EAPOL -> the frame was DROPPED entirely.
#  - Using spr262 = machdr_off would have DUPLICATED the bytes cmd=1 already copied
#    (the cmd=1 lookahead delivers ~96 of the 143-byte EAPOL; only ~47 incl the MIC
#    is missing).
#
# This fix (confirmed against the binary, NOT the emulator):
#  - Uses spr262 = spr1e2 (MAC-header offset) as the cmd=7 source -- the IV-free
#    analog of the working protected path (which uses spr1e2+0x10). On-device,
#    spr262 = spr00c gave spr261 = framelen - spr00c ~ 0 (the 0B97 guard skipped the
#    kick: spr00c/RXE_RXCNT counts ~the full received frame, NOT the lookahead).
#    spr262 = spr1e2 gives spr261 = framelen - spr1e2 (~105) so the kick fires.
#  - Bypasses the 0B95 gate via [0x841] bit7 (a bit never read or written anywhere
#    else in the ucode -- bit4 is written at 0CF5, so it is NOT used), so NO AMSDU
#    bit is set and the host does not drop the frame.
#  - Relies on the existing 0B97 runt guard (spr261 = framelen - spr00c <= 14 ->
#    skip) to self-protect frames already fully captured by the lookahead (e.g.
#    beacons that also reach 0AAE with no cipher key give spr261~0 -> no double copy).
#
# Flow:
#   0AAE jzx spr244 bit7 ->1431  (unprotected -> stub; protected falls through to 0AAF)
#   1431 spr262 = spr00c         (cmd=7 source = live lookahead end)
#   1432 [0x86B] = framelen (r26)
#   1433 [0x841] bit7 = 1        (free discriminator; NOT the AMSDU bit0)
#   1434 je -> 0AB5              (back to shared landing; 0B85 sets spr1e0 etc.)
#   0B95 je -> 1435             (route both paths into the kick gate)
#   1435 jnzx [0x841] bit0 ->0B96 (protected -> kick, byte-identical to stock)
#   1436 jnzx [0x841] bit7 ->0B96 (our unprotected -> kick, no AMSDU bit)
#   1437 je -> 0B99             (neither -> skip kick, stock behaviour)
#   then 0B96 spr261 = [0x86B]-spr262 = framelen - spr00c (remainder incl MIC);
#        0B97 runt guard; 0B98 cmd=7 kick; 0D0C delivers the grown length.
# Protected path byte-identical to stock.
#
# Usage: bcm4358-ucode-fullrx-fix.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-fullrx: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
UCODE_BASE_IN_FW = 0x8c9c0
base = 0 if len(d) < 0x20000 else UCODE_BASE_IN_FW
# (instr_index, old_hex, new_hex, label) -- verified vs ucode_real.bin and
# re-decoded with d11dasm.py (arch15).
patches = [
    (0x0AAE, "b50a0013c9030200", "31140013c9030200", "0AAE jzx spr244 bit7 ->1431 (unprotected -> stub)"),
    (0x1431, "8017009705b00000", "6212008b47e00000", "1431 spr262 = spr1e2 (machdr_off; IV-free analog of the working protected path)"),
    (0x1432, "53342c005e680000", "6b08006b5ee00000", "1432 [0x86B] = r26 (framelen)"),
    (0x1433, "1211000360bc0100", "41280805e0830100", "1433 [0x841] bit7 = 1 (free discriminator, NOT AMSDU bit0)"),
    (0x1434, "1511000360bc0100", "b50af0025e680000", "1434 je r0,r0 ->0AB5 (back to shared landing)"),
    (0x0B95, "990b000721000200", "3514f0025e680000", "0B95 je r0,r0 ->1435 (route into kick gate)"),
    (0x1435, "6410009b05b00000", "960b000721800200", "1435 jnzx [0x841] bit0 ->0B96 (protected kick)"),
    (0x1436, "3e14002345000200", "960b0007a1830200", "1436 jnzx [0x841] bit7 ->0B96 (our unprotected kick)"),
    (0x1437, "8117001f45b00000", "990bf0025e680000", "1437 je r0,r0 ->0B99 (neither -> skip kick)"),
]
if bytes(d[base:base+8]) != bytes.fromhex("4e10000360bc0100"):
    sys.stderr.write("ucode-fullrx: ucode anchor not at base 0x%x in %s -- aborting\n" % (base, path))
    sys.exit(1)
for idx, old_h, new_h, label in patches:
    off = base + idx * 8
    cur = bytes(d[off:off+8])
    if cur == bytes.fromhex(new_h):
        print("ucode-fullrx: %s @0x%x already patched [%s]" % (path, off, label)); continue
    if cur != bytes.fromhex(old_h):
        sys.stderr.write("ucode-fullrx: %s @0x%x expected %s got %s [%s] -- aborting\n"
                         % (path, off, old_h, cur.hex(), label)); sys.exit(1)
    d[off:off+8] = bytes.fromhex(new_h)
    print("ucode-fullrx: patched %s @0x%x  %s" % (path, off, label))
open(path, 'wb').write(d)
PY
