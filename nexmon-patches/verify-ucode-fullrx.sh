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

INSTR = {  # measurement build v6 (body-DMA-kick class probe: hook 0CE3, latch [0x214])
    off(0x0CE3): "3114f0025e680000",
    off(0x1431): "100200976eb00000",
    off(0x1432): "1102000749b00000",
    off(0x1433): "120200d747b00000",
    off(0x1434): "36f47f4f08680000",
    off(0x1435): "1322004f08e00000",
    off(0x1436): "39143107c9680000",
    off(0x1437): "140200d747b00000",
    off(0x1438): "1522005708e00000",
    off(0x1439): "f011005b00b00000",
    off(0x143A): "e40cf0025e680000",
}
FIX = {    # delivery build v2 (0AAE+0B95 retargeted; live spr00c, bit7 gate bypass)
    off(0x0AAE): "31140013c9030200",
    off(0x1431): "6212008b47e00000",
    off(0x1432): "6b08006b5ee00000",
    off(0x1433): "41280805e0830100",
    off(0x1434): "b50af0025e680000",
    off(0x0B95): "3514f0025e680000",
    off(0x1435): "960b000721800200",
    off(0x1436): "960b0007a1830200",
    off(0x1437): "990bf0025e680000",
}

if uc[off(0x0AAE):off(0x0AAE)+8].hex() == FIX[off(0x0AAE)]:
    want, name = FIX, "FIX (full EAPOL delivery)"
elif uc[off(0x0CE3):off(0x0CE3)+8].hex() == INSTR[off(0x0CE3)]:
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
