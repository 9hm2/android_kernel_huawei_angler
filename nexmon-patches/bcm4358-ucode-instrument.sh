#!/usr/bin/env bash
# NON-DESTRUCTIVE d11 ucode INSTRUMENTATION v3 (RXLEN probe) -- measure, do not
# change behaviour.
#
# On-device proof retired the 0B95/DAGG model: the unprotected EAPOL never reaches
# 0B95 (only 34-byte frames do). Its REAL retirement path is
#   0D05 -> 0D0C (RxFrameSize [0x838] = spr00c = 143) -> 0D0E calls-> 102F
# Subroutine 102F runs for EVERY frame. The per-MPDU host body-copy kick is
#   1034 (spr260=7), gated by 1033 (jnzx spr263/DAGG_STAT bit12 -> 1035 skip).
# Hypothesis: on plaintext, DAGG_STAT bit12 is SET so 1033 skips the 1034 kick and
# the host gets only the ~96-byte cmd=1 lookahead; spr264 (DAGG_LEN = bytes the
# DAGG pushed to the host) = 96, while spr00c/RxFrameSize = 143 (full). Protected
# keeps the decrypt FIFO busy so bit12 is clear, 1034 fires, full body delivered.
#
# We hook 1032 (inside 102F, on the EAPOL's actual path), stamp the live RX-length
# state into free low SHM [0x208]..[0x20F] (host bytes 0x410..0x41F), FAITHFULLY
# replicate the displaced 1032, then return to 1033. Behaviour byte-identical (no
# [0x841] bit0 write) -> cannot drop frames or break Wi-Fi.
#
# Read back: the ARM diag SHM snapshot (cmd 0x606, bytes [16..31]) already covers
# 0x410..0x41F, OR directly: ucmread wlan0 0x410 8 0x604
#   word0 [0x208]=0x03A5 MAGIC (LE a5 03)
#   word1 [0x209]=spr264 (DAGG_LEN, host bytes) <-- expect 96 plaintext / 143 protected
#   word2 [0x20A]=spr263 (DAGG_STAT; bit12 = done gate read at 1033)
#   word3 [0x20B]=spr00c (RXE_RXCNT, full pull = 143)
#   word4 [0x20C]=[0x838] (RxFrameSize = 143)
#   word5 [0x20D]=[0x841] (bit0 gate / bit1 protected tag)
#   word6 [0x20E]=spr262 (DAGG_SH_OFFSET)
#   word7 [0x20F]=spr211 (framelen)
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
# re-decoded with d11dasm.py (arch15). Hooks 1032 (102F, the EAPOL's real path).
patches = [
    (0x1032, "0490000660800100", "3114f0025e680000", "1032 je r0,r0 ->1431 (hook the EAPOL path in 102F)"),
    (0x1431, "8017009705b00000", "080200976eb00000", "1431 [0x208]=0x3A5 MAGIC (LE a5 03)"),
    (0x1432, "53342c005e680000", "0902009349b00000", "1432 [0x209]=spr264 (DAGG_LEN = host bytes)"),
    (0x1433, "1211000360bc0100", "0a02008f49b00000", "1433 [0x20A]=spr263 (DAGG_STAT, bit12 gate)"),
    (0x1434, "1511000360bc0100", "0b02003340b00000", "1434 [0x20B]=spr00c (RXE_RXCNT full pull)"),
    (0x1435, "6410009b05b00000", "0c0200e320b00000", "1435 [0x20C]=[0x838] (RxFrameSize)"),
    (0x1436, "3e14002345000200", "0d02000721b00000", "1436 [0x20D]=[0x841] (gate bit0 / tag bit1)"),
    (0x1437, "8117001f45b00000", "0e02008b49b00000", "1437 [0x20E]=spr262 (DAGG_SH_OFFSET)"),
    (0x1438, "8037f09205e80000", "0f02004748b00000", "1438 [0x20F]=spr211 (framelen)"),
    (0x1439, "3c140003de6a0000", "0490000660800100", "1439 orx 0,0,0x1,spr004,spr004 (replicate displaced 1032)"),
    (0x143A, "451100035eb00000", "3310f0025e680000", "143A je r0,r0 ->1033 (return to stock flow)"),
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
