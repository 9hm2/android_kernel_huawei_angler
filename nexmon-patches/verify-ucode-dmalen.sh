#!/usr/bin/env bash
# CI guard: assert the d11 ucode DMALEN efficacy test is embedded in the FINAL
# firmware. Decompress the nexmon-recompressed ucode blob and verify both
# 0x01C8 (file 0xE40) and 0x01CA (file 0xE50) are now `or 0x40,0x0,spr223`.
# Prints the built fw md5 so an on-device `md5sum` confirms what flashed.
#
# Usage: verify-ucode-dmalen.sh <fw_bcmdhd.bin>
set -euo pipefail
FW="${1:?usage: $0 <fw_bcmdhd.bin>}"

python3 - "$FW" <<'PY'
import sys, zlib, hashlib
d = open(sys.argv[1], 'rb').read()
i = d.find(b'\x78\x9c', 0x8d000)
if i < 0:
    sys.exit("::error::ucode-guard: no compressed ucode blob found in built fw")
uc = zlib.decompress(d[i:])
NEW = bytes.fromhex("2312000361b00000")   # or 0x40,0x0,spr223
a, b = uc[0xe40:0xe48], uc[0xe50:0xe58]
print("ucode-guard: blob@0x%x len 0x%x; 0xE40=%s 0xE50=%s" % (i, len(uc), a.hex(), b.hex()))
print("ucode-guard: built fw md5 =", hashlib.md5(d).hexdigest())
if a != NEW or b != NEW:
    sys.exit("::error::ucode-guard: DMALEN test NOT embedded (01C8/01CA not or 0x40,spr223)")
print("ucode-guard: DMALEN efficacy test confirmed embedded (spr223=0x40 at 01C8/01CA).")
PY
