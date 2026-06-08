#!/usr/bin/env bash
# CI guard: assert the d11 ucode init self-loop PROBE is embedded in the FINAL
# firmware. Decompress the ucode blob and verify 0x0001 (file 0x8) is the
# self-loop `jext 0x7F ->0001`. Prints the built fw md5.
# Usage: verify-ucode-hang.sh <fw_bcmdhd.bin>
set -euo pipefail
FW="${1:?usage: $0 <fw_bcmdhd.bin>}"
python3 - "$FW" <<'PY'
import sys, zlib, hashlib
d = open(sys.argv[1], 'rb').read()
i = d.find(b'\x78\x9c', 0x8d000)
if i < 0:
    sys.exit("::error::ucode-guard: no compressed ucode blob found in built fw")
uc = zlib.decompress(d[i:])
got = uc[0x8:0x10]
print("ucode-guard: blob@0x%x len 0x%x; 0x0008=%s" % (i, len(uc), got.hex()))
print("ucode-guard: built fw md5 =", hashlib.md5(d).hexdigest())
if got != bytes.fromhex("0100f002debf0300"):
    sys.exit("::error::ucode-guard: init self-loop probe NOT embedded at 0x0001")
print("ucode-guard: init self-loop PROBE confirmed embedded (PSM will hang at boot if loaded).")
PY
