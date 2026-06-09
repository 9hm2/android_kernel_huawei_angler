#!/usr/bin/env bash
# d11 ucode stamp: write the per-frame RX-FIFO MAC-header offset spr1e2 to free
# SHM [0x208] (host byte 0x410) so the ARM monitor hook can locate this frame in
# the d11 receive-FIFO SRAM and dump it (the full plaintext body -- Nonce+MIC --
# is resident there at spr1e2+k on the no-key path; we just need the right objmem
# select). 4 words, byte-identical behaviour (hook 1032 in sub 102F, replicate the
# displaced 1032, return to 1033).
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
patches = [
    (0x1032, "0490000660800100", "3114f0025e680000", "1032 je r0,r0 ->1431 (hook finalizer 102F)"),
    (0x1431, "8017009705b00000", "0802008b47b00000", "1431 [0x208]=spr1e2 (RX-FIFO MAC-hdr offset)"),
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
