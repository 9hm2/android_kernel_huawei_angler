#!/usr/bin/env bash
# NON-DESTRUCTIVE d11 ucode INSTRUMENTATION v2 (measure, do not change behaviour).
#
# Relocated, HOST-READABLE version. The prior instrumentation stamped to ucode
# words [0x890]+, which lie ABOVE the ~0x800-word host-SHM window, so wlc_read_shm
# returned a constant. This version stamps into the verified-free LOW block
# [0x200]..[0x207] (host SHM byte 0x400..0x40F) and writes a MAGIC marker so the
# block can be located even if the word->byte SHM mapping is offset.
#
# Both RX paths converge at the cmd=7 kick gate 0B95. We retarget 0B95 into the
# orphaned dead block 1431-143A, STAMP the live DAGG state, then FAITHFULLY
# re-implement the original 0B95 gate (`if [0x841] bit0==0 -> 0B99 else -> 0B96`).
# We do NOT set [0x841] bit0, so this cannot trigger the AMSDU drop or change
# behaviour -- it only adds writes to free low SHM scratch.
#
# Read back (host SHM byte 0x400 = word 0x200), 8 words:
#     ucmread wlan0 0x400 8 0x603
#   word0 [0x200] = 0x03A5  MAGIC (LE bytes A5 03) -- confirms the block/mapping
#   word1 [0x201] = spr262  (DAGG_SH_OFFSET / cmd=7 source offset)
#   word2 [0x202] = [0x86B] (body total length)
#   word3 [0x203] = [0x86B]-spr262 (bytes-to-copy)
#   word4 [0x204] = spr00c  (RXE_RXCNT = cmd=1 lookahead bytes already copied)  <-- KEY
#   word5 [0x205] = [0x841] (bit0=kick gate, bit1=protected => PATH TAG)
#   word6 [0x206] = spr211  (framelen)
#   word7 [0x207] = [0x838] (RxFrameSize)
# If word0 is not 0x03A5 at byte 0x400, sweep host bytes 0x000..0x1000 for "a5 03".
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
# (instr_index, old_hex, new_hex, label) -- verified vs ucode_real.bin and
# re-decoded with d11dasm.py (arch15). Stamps to host-readable SHM word 0x200+.
patches = [
    (0x0B95, "990b000721000200", "3114f0025e680000", "0B95 je r0,r0 ->1431 (hook both paths)"),
    (0x1431, "8017009705b00000", "000200976eb00000", "1431 [0x200]=0x3A5 MAGIC (LE a5 03)"),
    (0x1432, "53342c005e680000", "0102008b49b00000", "1432 [0x201]=spr262 (DAGG_SH_OFFSET)"),
    (0x1433, "1211000360bc0100", "020200af21b00000", "1433 [0x202]=[0x86B] (body total len)"),
    (0x1434, "1511000360bc0100", "03424cae21e80000", "1434 [0x203]=[0x86B]-spr262 (bytes-to-copy)"),
    (0x1435, "6410009b05b00000", "0402003340b00000", "1435 [0x204]=spr00c (cmd=1 lookahead bytes)"),
    (0x1436, "3e14002345000200", "0502000721b00000", "1436 [0x205]=[0x841] (gate bit0 / tag bit1)"),
    (0x1437, "8117001f45b00000", "0602004748b00000", "1437 [0x206]=spr211 (framelen)"),
    (0x1438, "8037f09205e80000", "070200e320b00000", "1438 [0x207]=[0x838] (RxFrameSize)"),
    (0x1439, "3c140003de6a0000", "990b000721000200", "1439 jzx [0x841] bit0 ->0B99 (gate replicate)"),
    (0x143A, "451100035eb00000", "960bf0025e680000", "143A je r0,r0 ->0B96 (gate replicate)"),
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
