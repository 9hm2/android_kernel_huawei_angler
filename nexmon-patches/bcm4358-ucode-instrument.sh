#!/usr/bin/env bash
# NON-DESTRUCTIVE d11 ucode INSTRUMENTATION v6 (body-DMA-kick class probe).
#
# THE decisive last-lead measurement. Hook 0CE3 -- the sole body-DMA kick site
# (or [0x16],0x0,spr1f0) on the body-pull path 0CD0-0CE3, where spr1f5 holds the
# FULL-body length. For every frame that fires a body DMA, stamp its FC class
# (spr241), the body length (spr1f5), and a saturating counter; and LATCH the
# body length + a counter ONLY when the class is the EAPOL data class (0x188).
# The real kick is replicated verbatim at 1439 -> behaviour byte-identical.
#
# Decision: read host byte 0x420 (objmem sel 0x10000, word*2):
#   0x420=[0x210] MAGIC 0x03A5 (LE a5 03)
#   0x422=[0x211] spr241 of last kicking frame (0x0080=beacon/mgmt, 0x0188=EAPOL)
#   0x424=[0x212] spr1f5 body length (bodywords+1)
#   0x426=[0x213] total body-kick counter (saturates 0x3FF)
#   0x428=[0x214] EAPOL body-length latch -- NONZERO IFF an EAPOL ever did a body DMA
#   0x42A=[0x215] EAPOL body-kick counter
# If 0x428/0x42A stay 0 across many handshakes while 0x426 climbs (beacons/protected
# kicking), the plaintext EAPOL data class NEVER reaches the body DMA -> the
# mgmt-full/data-short split is hardware-gated. (Force-fix is impossible: the body-DMA
# command word [0x16] is built solely from spr041, a hw decrypt-state reg the ucode
# never writes; for a plaintext frame it is a no-op.)
#   ucmread wlan0 0x420 12 0x604
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
# (instr_index, old_hex, new_hex, label) -- verified vs ucode_real.bin + re-decoded.
patches = [
    (0x0CE3, "f011005b00b00000", "3114f0025e680000", "0CE3 je r0,r0 ->1431 (HOOK the body-DMA kick)"),
    (0x1431, "8017009705b00000", "100200976eb00000", "1431 [0x210]=0x3A5 MAGIC"),
    (0x1432, "53342c005e680000", "1102000749b00000", "1432 [0x211]=spr241 (last kicking class)"),
    (0x1433, "1211000360bc0100", "120200d747b00000", "1433 [0x212]=spr1f5 (body length)"),
    (0x1434, "1511000360bc0100", "36f47f4f08680000", "1434 je [0x213],0x3FF ->1436 (saturate)"),
    (0x1435, "6410009b05b00000", "1322004f08e00000", "1435 [0x213]+=1 (total kick counter)"),
    (0x1436, "3e14002345000200", "39143107c9680000", "1436 jne spr241,0x188 ->1439 (EAPOL gate)"),
    (0x1437, "8117001f45b00000", "140200d747b00000", "1437 [0x214]=spr1f5 (EAPOL body-len latch)"),
    (0x1438, "8037f09205e80000", "1522005708e00000", "1438 [0x215]+=1 (EAPOL kick counter)"),
    (0x1439, "3c140003de6a0000", "f011005b00b00000", "1439 or [0x16],0x0,spr1f0 (REPLICATE the kick)"),
    (0x143A, "451100035eb00000", "e40cf0025e680000", "143A je r0,r0 ->0CE4 (return to stock flow)"),
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
