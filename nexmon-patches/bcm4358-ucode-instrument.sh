#!/usr/bin/env bash
# NON-DESTRUCTIVE d11 ucode INSTRUMENTATION v4 (tail re-pull locator).
#
# On-device proof: the full foreign EAPOL (143 bytes incl Key MIC) IS resident in
# d11 shared SRAM (RXE pulled it; spr00c/RxFrameSize=143), but only the ~96-byte
# lookahead is DMA'd to the host -- full delivery is coupled to a real key-matched
# decrypt, which a foreign EAPOL never gets, so a ucode null-cipher is impossible.
# The fix is an ARM-side re-pull of the missing tail from d11 SRAM via objmem
# (select 0x10000, the proven working object). The frame's MAC header lives at
# SRAM byte offset spr1e2 within that object.
#
# This build STAMPS spr1e2 into free SHM word [0x208] (host byte 0x410) so the ARM
# monitor hook can read it and dump the frame from objmem(0x10000, spr1e2 + k) to
# CONFIRM the address (full frame incl a non-zero MIC tail past byte 96) before we
# wire up the actual re-pull/splice. Behaviour byte-identical (hooks 1032 inside
# sub 102F, faithfully replicates the displaced 1032, returns to 1033) -> cannot
# drop frames or break Wi-Fi.
#
# Usage: bcm4358-ucode-instrument.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-instrument: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
UCODE_BASE_IN_FW = 0x8c9c0
base = 0 if len(d) < 0x20000 else UCODE_BASE_IN_FW
# (instr_index, old_hex, new_hex, label) -- verified vs ucode_real.bin + re-decoded.
patches = [
    (0x1032, "0490000660800100", "3114f0025e680000", "1032 je r0,r0 ->1431 (hook the EAPOL path in 102F)"),
    (0x1431, "8017009705b00000", "0802008b47b00000", "1431 [0x208]=spr1e2 (frame MAC-hdr offset in d11 SRAM)"),
    (0x1432, "53342c005e680000", "0490000660800100", "1432 orx 0,0,0x1,spr004,spr004 (displaced 1032)"),
    (0x1433, "1211000360bc0100", "3310f0025e680000", "1433 je r0,r0 ->1033 (return to stock flow)"),
]
if bytes(d[base:base+8]) != bytes.fromhex("4e10000360bc0100"):
    sys.stderr.write("ucode-instrument: ucode anchor not at base 0x%x in %s -- aborting\n" % (base, path))
    sys.exit(1)
for idx, old_h, new_h, label in patches:
    off = base + idx * 8
    cur = bytes(d[off:off+8])
    if cur == bytes.fromhex(new_h):
        print("ucode-instrument: %s @0x%x already patched [%s]" % (path, off, label)); continue
    if cur != bytes.fromhex(old_h):
        sys.stderr.write("ucode-instrument: %s @0x%x expected %s got %s [%s] -- aborting\n"
                         % (path, off, old_h, cur.hex(), label)); sys.exit(1)
    d[off:off+8] = bytes.fromhex(new_h)
    print("ucode-instrument: patched %s @0x%x  %s" % (path, off, label))
open(path, 'wb').write(d)
PY
