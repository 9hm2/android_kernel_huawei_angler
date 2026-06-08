#!/usr/bin/env bash
# CI guard: assert the d11 ucode spr064 body-pull FIX is embedded in the FINAL
# firmware. Decompress the nexmon-recompressed ucode blob out of the linked
# fw_bcmdhd.bin and verify instruction 0x0B86 (file offset 0x5C30) is now an
# `add ...,spr064` (any of variants A/B/C), not the original redundant orx.
# Prints the built fw md5 so an on-device `md5sum` confirms exactly what flashed.
#
# Usage: verify-ucode-spr064.sh <fw_bcmdhd.bin>
set -euo pipefail
FW="${1:?usage: $0 <fw_bcmdhd.bin>}"

python3 - "$FW" <<'PY'
import sys, zlib, hashlib
d = open(sys.argv[1], 'rb').read()
i = d.find(b'\x78\x9c', 0x8d000)            # nexmon-recompressed ucode blob
if i < 0:
    sys.exit("::error::ucode-guard: no compressed ucode blob found in built fw")
uc = zlib.decompress(d[i:])
got = uc[0x5c30:0x5c38]
variants = {
    "64503cae00e00000": "A add [0x2B],spr1e2,spr064",
    "641000af00e00000": "C add [0x2B],0x0,spr064",
    "64504cae00e00000": "B add [0x2B],spr262,spr064",
}
hexv = got.hex()
print("ucode-guard: blob@0x%x len 0x%x; 0x5c30=%s" % (i, len(uc), hexv))
print("ucode-guard: built fw md5 =", hashlib.md5(d).hexdigest())
if hexv == "41280801e0810100":
    sys.exit("::error::ucode-guard: 0B86 still the original orx -- spr064 FIX NOT applied")
if hexv not in variants:
    sys.exit("::error::ucode-guard: 0B86 = %s is neither original nor a known spr064 variant" % hexv)
print("ucode-guard: spr064 body-pull fix confirmed embedded [variant %s]." % variants[hexv])
PY
