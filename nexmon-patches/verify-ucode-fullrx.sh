#!/usr/bin/env bash
# CI guard: assert the active d11 ucode patch (INSTRUMENTATION or FIX) is fully
# embedded in the FINAL firmware. Decompress the ucode blob and verify all words
# of whichever patch is present (auto-detected by its entry retarget). Prints the
# fw md5 (so it matches the on-device `md5sum /vendor/firmware/fw_bcmdhd.bin`).
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
print("ucode-guard: blob@0x%x len 0x%x" % (i, len(uc)))
print("ucode-guard: built fw md5 =", hashlib.md5(d).hexdigest())

# instruction index*8 = byte offset in the ucode image
def off(idx): return idx * 8

INSTR = {  # measurement build (0B95 retargeted to the stamp block)
    off(0x0B95): "3114f0025e680000",
    off(0x1431): "9008008b49b00000",
    off(0x1432): "910800af21b00000",
    off(0x1433): "92484cae21e80000",
    off(0x1434): "9308003340b00000",
    off(0x1435): "9408000721b00000",
    off(0x1436): "950800e320b00000",
    off(0x1437): "9608004748b00000",
    off(0x1438): "990b000721000200",
    off(0x1439): "960bf0025e680000",
}
FIX = {    # delivery build (0AAE retargeted to the IV-free body-copy stub)
    off(0x0AAE): "31140013c9030200",
    off(0x1431): "6212008b47e00000",
    off(0x1432): "6b08006b5ee00000",
    off(0x1433): "4128080560800100",
    off(0x1434): "b50af0025e680000",
}

if uc[off(0x0AAE):off(0x0AAE)+8].hex() == FIX[off(0x0AAE)]:
    want, name = FIX, "FIX (full EAPOL delivery)"
elif uc[off(0x0B95):off(0x0B95)+8].hex() == INSTR[off(0x0B95)]:
    want, name = INSTR, "INSTRUMENTATION (DAGG SHM stamp)"
else:
    sys.exit("::error::ucode-guard: neither FIX nor INSTRUMENTATION entry retarget found")

print("ucode-guard: detected active patch =", name)
ok = True
for o, exp in sorted(want.items()):
    got = uc[o:o+8].hex()
    print("ucode-guard:   0x%05x = %s (want %s) %s" % (o, got, exp, "OK" if got == exp else "MISMATCH"))
    if got != exp:
        ok = False
if not ok:
    sys.exit("::error::ucode-guard: active ucode patch NOT fully embedded")
print("ucode-guard:", name, "confirmed embedded.")
PY
