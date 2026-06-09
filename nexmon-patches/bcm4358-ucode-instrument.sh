#!/usr/bin/env bash
# NON-DESTRUCTIVE d11 ucode INSTRUMENTATION v5 (mgmt-vs-data write-length probe).
#
# Decisive test for the last lead: on-device, MANAGEMENT frames (beacons) are
# written to d11 SRAM FULL, but plaintext DATA frames (foreign WPA2 EAPOL) are
# header-only (body/Nonce/MIC = zeros). The host write length is spr1f5: set once
# class-blind to 0x13 (lookahead) at 0A94, and only lengthened by the runtime-
# gated body-pull at 0CD0/0CE2. If the BEACON reaches the finalizer (sub 102F)
# with spr1f5 = full body length while the EAPOL shows spr1f5 = 0x13, then 0CD0 is
# a ucode-reachable mechanism and a real patch is constructible; if even the
# BEACON shows 0x13, the mgmt-full/data-short split is a hardware RXE FIFO drain
# the PSM does not meter -> confirmed dead-end for a ucode length patch.
#
# Hook 1032 (in sub 102F, the per-frame finalizer both classes reach), stamp the
# write-length state to free SHM [0x208]..[0x20F] (host bytes 0x410..0x41F),
# faithfully replicate the displaced 1032, return to 1033. Behaviour byte-
# identical -> cannot drop frames.
#
# Stamps (read host byte 0x410, e.g. `ucmread wlan0 0x410 16 0x604`):
#   [0x208]=0x03A5 MAGIC | [0x209]=spr1f5 (host write length; 0x13=lookahead) |
#   [0x20A]=[0x16] body-DMA cmd word | [0x20B]=[0x1F,off5] body-pull predicate |
#   [0x20C]=spr263 DAGG_STAT | [0x20D]=[0x838] RxFrameSize | [0x20E]=spr241 FC
#   class | [0x20F]=spr1e2 MAC-hdr SRAM offset.
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
    (0x1032, "0490000660800100", "3114f0025e680000", "1032 je r0,r0 ->1431 (hook finalizer 102F)"),
    (0x1431, "8017009705b00000", "080200976eb00000", "1431 [0x208]=0x3A5 MAGIC"),
    (0x1432, "53342c005e680000", "090200d747b00000", "1432 [0x209]=spr1f5 (host write length)"),
    (0x1433, "1211000360bc0100", "0a02005b00b00000", "1433 [0x20A]=[0x16] (body-DMA cmd word)"),
    (0x1434, "1511000360bc0100", "0b02007f5ab00000", "1434 [0x20B]=[0x1F,off5] (body-pull predicate)"),
    (0x1435, "6410009b05b00000", "0c02008f49b00000", "1435 [0x20C]=spr263 (DAGG_STAT)"),
    (0x1436, "3e14002345000200", "0d0200e320b00000", "1436 [0x20D]=[0x838] (RxFrameSize)"),
    (0x1437, "8117001f45b00000", "0e02000749b00000", "1437 [0x20E]=spr241 (FC class hw reg)"),
    (0x1438, "8037f09205e80000", "0f02008b47b00000", "1438 [0x20F]=spr1e2 (MAC-hdr SRAM offset)"),
    (0x1439, "3c140003de6a0000", "0490000660800100", "1439 orx 0,0,0x1,spr004,spr004 (displaced 1032)"),
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
