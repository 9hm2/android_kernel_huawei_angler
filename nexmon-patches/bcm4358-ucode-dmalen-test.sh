#!/usr/bin/env bash
# DECISIVE EFFICACY TEST for the BCM4358 monitor-mode 86-byte truncation.
#
# Why: SEVEN ucode patches (0A7E/0840/0AAE/0B95/0D06/0B86...) all produced a
# byte-identical 86-byte capture. RE then showed they ALL sat in the 0A73-0B95
# band -- the TX-template / ACK-response engine -- NOT the host RX->host DMA
# path. The real RX-to-host descriptor is built at 0x01C3 (reached every frame
# via 0x03CE calls ->01C3); the DMA byte count is spr223, set at:
#     01C8: sub spr211,0x4,spr223     ; spr223 = RXE framelen - 4
#     01CA: or  spr211,0x0,spr223     ; (the "full length" arm of the 01C9 gate)
# None of the 7 patches touched spr223. This test forces spr223 = 0x40 (64) at
# BOTH sites, on the UNIVERSAL RX path, so the effect cannot be "off path".
#
# Read the result from captured frame lengths (tshark):
#   * ALL frames (incl. your own protected data RX) become <= ~64 bytes
#       -> RAM-ucode patching WORKS and spr223/01C8 is the host-DMA length
#          governor. Fix = set the real full length here (not 86).
#   * Protected/data RX truncates to ~64 but foreign EAPOL stays at exactly 86
#       -> patching WORKS, but EAPOL's 86 is bounded by a SEPARATE RXE/ARM
#          lookahead path -> pivot there.
#   * NOTHING changes (frames still full / EAPOL still 86)
#       -> RAM-ucode patching is NOT taking effect on this chip -> debug the
#          decompress-into-IMEM deployment, stop patching ucode blindly.
#
# Safe: spr223 is a DMA byte count; 0x40 yields short RX frames (degraded Wi-Fi
# RX) but no illegal opcode / control-flow change. A normal fw_bcmdhd.bin
# reflash fully recovers. 2 edits, reversible.
#
# Usage: bcm4358-ucode-dmalen-test.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-dmalen: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
NEW = "2312000361b00000"   # or 0x40,0x0,spr223
patches = [
    ("2392004748e80000", NEW, "01C8 sub spr211,0x4,spr223 -> or 0x40,0x0,spr223"),
    ("2312004748b00000", NEW, "01CA or spr211,0x0,spr223  -> or 0x40,0x0,spr223"),
]
done = 0
for old_h, new_h, label in patches:
    old, new = bytes.fromhex(old_h), bytes.fromhex(new_h)
    n_old = d.count(old)
    if n_old == 0 and d.count(new) >= 1:
        print("ucode-dmalen: %s already has [%s]" % (path, label)); done += 1; continue
    if n_old != 1:
        sys.stderr.write("ucode-dmalen: expected exactly 1 site for %s in %s, found %d -- aborting\n"
                         % (label, path, n_old)); sys.exit(1)
    off = d.find(old); d[off:off+8] = new
    print("ucode-dmalen: patched %s @0x%x  %s" % (path, off, label)); done += 1
if done == len(patches):
    open(path, 'wb').write(d)
PY
