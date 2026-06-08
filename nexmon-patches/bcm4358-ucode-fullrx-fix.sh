#!/usr/bin/env bash
# THE FIX (static-RE'd, verified): deliver the FULL unprotected foreign DATA frame
# (WPA2 EAPOL incl. Key MIC) to the host monitor on the BCM4358 d11, by firing the
# d11 DAGG body copy (cmd=7) on the plaintext RX path with IV-free bookkeeping.
#
# Mechanism (confirmed from the binary, NOT the emulator):
#   The body copy at 0B96-0B98 (spr260=7) is gated at 0B95 by [0x841] bit0, which
#   is set ONLY on the protected path (0AB1). Protected frames also set spr262 =
#   machdr_off+0xC (CCMP IV skip) and [0x86B] = framelen+0xE. The unprotected path
#   (0AAE jumps to 0AB5) skips all of that, so [0x841] bit0 stays 0 and the body
#   copy never fires -> only the ~86B cmd=1 lookahead reaches the host (no MIC).
#
# The fix retargets 0AAE's UNPROTECTED branch into the orphaned dead block at 1431
# (provably unreferenced: 1430 is a rets, nothing outside 1431-143F targets it) and
# runs an IV-FREE setup, then returns to the shared landing 0AB5:
#   1431: spr262  = machdr_off   (NO +0xC IV skip)
#   1432: [0x86B] = framelen     (NO crypto trailer)
#   1433: [0x841] bit0 = 1       (enable the 0B95 kick gate; bit0 alone, not AMSDU bit1)
#   1434: je r0,r0 -> 0AB5       (return to shared path)
# Then 0B96 computes spr261 = [0x86B]-spr262 = framelen-machdr_off (full body), the
# 0B97 guard (`jles spr261,0xE -> 0B99`) drops runts, and 0B98 kicks cmd=7. The body
# APPENDS after the lookahead; spr00c grows to the full length; 0D0C delivers it.
#
# Protected path: byte-for-byte unchanged (still falls through 0AAE->0AAF->0AB1).
# spr064 is NOT touched (it is the WEP/crypto FIFO pointer, unused by the DAGG cmd=7
# copy -- the source of the earlier "stale spr262" corruption was wrongly blamed on
# a missing spr064 by the emulator).
#
# NOTE on the 0B97 runt guard: spr261 = framelen - machdr_off. For any real EAPOL
# frame framelen >> machdr_off so spr261 is comfortably positive; the 0B97 `jles
# 0xE` guard skips frames whose body is <=14 bytes (incl. an underflow on a
# malformed runt), so the DAGG copy count never goes wild. This is the same guard
# the working protected path relies on.
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
# (instr_index, old_hex, new_hex, label) -- all verified against ucode_real.bin
# and re-decoded with d11dasm.py (arch15).
patches = [
    (0x0AAE, "b50a0013c9030200", "31140013c9030200", "0AAE jzx spr244 bit7 ->1431 (retarget UNPROTECTED branch to fix stub)"),
    (0x1431, "8017009705b00000", "6212008b47e00000", "1431 spr262 = spr1e2 (machdr_off, IV-free)"),
    (0x1432, "53342c005e680000", "6b08006b5ee00000", "1432 [0x86B] = r26 (framelen, no crypto trailer)"),
    (0x1433, "1211000360bc0100", "4128080560800100", "1433 [0x841] bit0 = 1 (enable 0B95 kick gate)"),
    (0x1434, "1511000360bc0100", "b50af0025e680000", "1434 je r0,r0 ->0AB5 (return to shared landing)"),
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
