#!/usr/bin/env bash
# CI guard: assert the d11 ucode full-RX fix is embedded in the FINAL firmware.
# Decompress the ucode blob and verify 0x0B85 (file 0x5C28) is now
# orx 4,4,0x1D,0x0,spr1e0 (spr1e0=0xD0, body-stream bit6 set). Prints fw md5.
# The on-device read-back offset is 0x5C28 (ucmread wlan0 0x5C28 8).
# Usage: verify-ucode-fullrx.sh <fw_bcmdhd.bin>
set -euo pipefail
FW="${1:?usage: $0 <fw_bcmdhd.bin>}"
python3 - "$FW" <<'PY'
import sys, zlib, hashlib
d = open(sys.argv[1], 'rb').read()
i = d.find(b'\x78\x9c', 0x8d000)
if i < 0:
    sys.exit("::error::ucode-guard: no compressed ucode blob found in built fw")
uc = zlib.decompress(d[i:])
aae = uc[0x5570:0x5578]   # 0AAE
b85 = uc[0x5c28:0x5c30]   # 0B85
print("ucode-guard: blob@0x%x len 0x%x; 0x5570=%s 0x5c28=%s" % (i, len(uc), aae.hex(), b85.hex()))
print("ucode-guard: built fw md5 =", hashlib.md5(d).hexdigest())
if aae != bytes.fromhex("b10a0013c9030200"):
    sys.exit("::error::ucode-guard: 0AAE not retargeted ->0AB1 (got %s)" % aae.hex())
if b85 != bytes.fromhex("e011007760a20100"):
    sys.exit("::error::ucode-guard: 0B85 not spr1e0=0xD0 (got %s)" % b85.hex())
print("ucode-guard: full-RX fix confirmed embedded (0AAE->0AB1 + 0B85 body-stream on).")
print("ucode-guard: on-device verify: ucmread wlan0 0x5570 8 -> b10a0013c9030200; "
      "ucmread wlan0 0x5C28 8 -> e011007760a20100")
PY
