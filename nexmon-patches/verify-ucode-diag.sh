#!/usr/bin/env bash
# CI guard: assert the d11 ucode RXLEN-DIAG patch is actually embedded in the
# BUILT firmware. Decompress the nexmon-recompressed ucode blob out of the
# linked fw_bcmdhd.bin and verify the patched instruction word at 0x6830
# (= idx 0x0D06: add spr00c,0x80,r33). Catches stale artifacts / a compression
# step that silently dropped the patch, and prints the built fw md5 so an
# on-device `md5sum` can confirm exactly what is flashed.
#
# Usage: verify-ucode-diag.sh <fw_bcmdhd.bin>
set -euo pipefail
FW="${1:?usage: $0 <fw_bcmdhd.bin>}"

python3 - "$FW" <<'PY'
import sys, zlib, hashlib
d = open(sys.argv[1], 'rb').read()
i = d.find(b'\x78\x9c', 0x8d000)            # nexmon-recompressed ucode blob
if i < 0:
    sys.exit("::error::ucode-guard: no compressed ucode blob found in built fw")
uc = zlib.decompress(d[i:])
got = uc[0x6830:0x6838]
ok = got == bytes.fromhex("a117103340e00000")   # 0D06 add spr00c,0x80,r33
print("ucode-guard: blob@0x%x len 0x%x; 0x6830=%s" % (i, len(uc), got.hex()))
print("ucode-guard: built fw md5 =", hashlib.md5(d).hexdigest())
if not ok:
    sys.exit("::error::ucode-guard: RXLEN-DIAG patch NOT present in built ucode")
print("ucode-guard: RXLEN-DIAG ucode patch confirmed embedded.")
PY
