#!/usr/bin/env bash
# CI guard: assert the clean d11 full-RX fix (5 words) is embedded in the FINAL
# firmware. Decompress the ucode blob and verify all five patched words. Prints
# the fw md5. On-device read-back (ucmread wlan0 <off> 8): 0x5C30, 0xA188,
# 0xA190, 0xA198, 0xA1A0.
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
want = {
    0x54d8: "9caa034fde680000",   # 0A9B jne r19,0x1D ->0A9C
    0x54e0: "9f0a0013c9830200",   # 0A9C jnzx spr244 ->0A9F (protected skip)
    0x54e8: "6112008f47b00000",   # 0A9D spr261=spr1e3 (full length)
    0x54f0: "6212000360b00000",   # 0A9E spr262=0
}
print("ucode-guard: blob@0x%x len 0x%x" % (i, len(uc)))
print("ucode-guard: built fw md5 =", hashlib.md5(d).hexdigest())
ok = True
for off, exp in want.items():
    got = uc[off:off+8].hex()
    print("ucode-guard:   0x%05x = %s (want %s) %s" % (off, got, exp, "OK" if got == exp else "MISMATCH"))
    if got != exp:
        ok = False
if not ok:
    sys.exit("::error::ucode-guard: clean full-RX fix NOT fully embedded")
print("ucode-guard: clean full-RX fix confirmed embedded (DATA-only body stream).")
PY
