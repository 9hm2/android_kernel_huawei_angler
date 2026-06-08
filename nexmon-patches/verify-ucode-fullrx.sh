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
    0x5c30: "315400ab5e680000",   # 0B86 je r42,0x2 ->1431
    0xa188: "4128080560880100",   # 1431 [0x841] bit0
    0xa190: "6212008b47b00000",   # 1432 spr262=spr1e2
    0xa198: "6bc8016b5ee00000",   # 1433 [0x86B]=r26+0xE
    0xa1a0: "870b000080bf0300",   # 1434 jext ->0B87
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
