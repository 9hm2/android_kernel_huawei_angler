#!/usr/bin/env bash
# NON-DESTRUCTIVE d11 ucode INSTRUMENTATION (measure, do not change behaviour).
#
# Replaces the broken offline emulator with REAL on-device measurement of the
# DAGG body-copy bookkeeping. Both the protected (full-delivery) and unprotected
# (truncated EAPOL) RX paths converge at the body-copy kick gate 0B95. We retarget
# 0B95 into the orphaned dead block at 1431, STAMP the live DAGG state into spare
# SHM words 0x890..0x896, then FAITHFULLY re-implement the original 0B95 gate
# (`if [0x841] bit0==0 -> 0B99 else -> 0B96`). Behaviour is byte-for-byte identical;
# the only added effect is 7 writes to never-referenced SHM scratch -> cannot break
# Wi-Fi.
#
# Read back from the device with the SHM-read ioctl (cmd 0x603). SHM word [0xNNN]
# is at byte offset 0xNNN*2, so word 0x890 = byte 0x1120:
#     ucmread wlan0 0x1120 8 0x603      # 8 words: 0x890..0x897
# Stamped (per received data frame; last one wins):
#   [0x890]=spr262(DAGG src off)  [0x891]=[0x86B](body len)
#   [0x892]=[0x86B]-spr262(bytes-to-copy)  [0x893]=spr00c(RXE_RXCNT bytes copied)
#   [0x894]=[0x841] (bit0=kick gate, bit1=protected => PATH TAG 1=prot/0=unprot)
#   [0x895]=[0x838](RxFrameSize so far)  [0x896]=spr211(framelen)
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
# (instr_index, old_hex, new_hex, label) -- all verified against ucode_real.bin
# and re-decoded with d11dasm.py (arch15).
patches = [
    (0x0B95, "990b000721000200", "3114f0025e680000", "0B95 je r0,r0 ->1431 (hook both paths into stamp block)"),
    (0x1431, "8017009705b00000", "9008008b49b00000", "1431 [0x890]=spr262 (DAGG_SH_OFFSET)"),
    (0x1432, "53342c005e680000", "910800af21b00000", "1432 [0x891]=[0x86B] (body total length)"),
    (0x1433, "1211000360bc0100", "92484cae21e80000", "1433 [0x892]=[0x86B]-spr262 (bytes-to-copy)"),
    (0x1434, "1511000360bc0100", "9308003340b00000", "1434 [0x893]=spr00c (RXE_RXCNT)"),
    (0x1435, "6410009b05b00000", "9408000721b00000", "1435 [0x894]=[0x841] (gate bit0 / path-tag bit1)"),
    (0x1436, "3e14002345000200", "950800e320b00000", "1436 [0x895]=[0x838] (RxFrameSize so far)"),
    (0x1437, "8117001f45b00000", "9608004748b00000", "1437 [0x896]=spr211 (framelen)"),
    (0x1438, "8037f09205e80000", "990b000721000200", "1438 jzx [0x841] bit0 ->0B99 (replicate gate: skip kick)"),
    (0x1439, "3c140003de6a0000", "960bf0025e680000", "1439 je r0,r0 ->0B96 (replicate gate: do kick)"),
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
