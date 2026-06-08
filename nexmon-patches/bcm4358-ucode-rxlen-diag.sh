#!/usr/bin/env bash
# DIAGNOSTIC ucode patch for the BCM4358 monitor-mode foreign-EAPOL truncation.
#
# Question this answers (decisively, in ONE on-device capture):
#   Is the truncation a REPORTING bug (the full frame body is already DMA'd into
#   host RAM but RxFrameSize under-reports it) or a COPY-ENGINE bug (only the
#   header is ever pulled out of the RX FIFO, so the body is genuinely absent)?
#
# Mechanism (RE'd, arch-15 disassembly):
#   RxFrameSize [0x838] -- the length the host/monitor clone uses -- is written
#   at instruction 0x0D0C from r33, and on the UNPROTECTED RX path r33 == spr00c
#   (the RXE hardware received-byte counter) set at 0x0D06:
#       0D06: or  spr00c, 0x0, r33          ; r33 = spr00c  (~86 for unprotected)
#   We change ONLY that one instruction to add a fixed +0x80 (128) bytes:
#       0D06: add spr00c, 0x80, r33         ; r33 = spr00c + 128
#   so an unprotected EAPOL monitor frame is reported as ~214 bytes instead of
#   ~86. Nothing else is touched -- no copy engine, no decrypt, no gating.
#
# Reading the result (inspect the captured EAPOL frame past on-air byte ~86):
#   * real Key-MIC / EAPOL key-data bytes present  -> the body WAS in host RAM,
#     only the reported length was short. Fix = report the full length (trivial,
#     safe, 1 instruction). BEST CASE.
#   * zeros / stale garbage                          -> the body was never pulled
#     from the FIFO; the WEP/copy engine must be triggered (harder fix).
#
# This is intentionally NOT a fix; it is the measurement that tells us which fix
# family to commit, avoiding another blind iteration. Protected/CCMP data frames
# take a different r33 source (spr263 at 0x0D09) so they are largely unaffected.
#
# The 8-byte signature is unique in both the extracted ucode (idx*8) and the
# firmware image, so we search-and-replace wherever it occurs.
#
# Usage: bcm4358-ucode-rxlen-diag.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail

F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-rxlen-diag: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
# 0x0D06: or spr00c,0x0,r33  ->  add spr00c,0x80,r33   (RxFrameSize += 128)
old = bytes.fromhex("a117003340b00000")
new = bytes.fromhex("a117103340e00000")
n_old, n_new = d.count(old), d.count(new)
if n_new >= 1 and n_old == 0:
    print("ucode-rxlen-diag: %s already patched" % path); sys.exit(0)
if n_old != 1:
    sys.stderr.write("ucode-rxlen-diag: expected exactly 1 site in %s, found "
                     "%d (and %d patched) -- aborting\n" % (path, n_old, n_new))
    sys.exit(1)
off = d.find(old); d[off:off+8] = new
open(path, 'wb').write(d)
print("ucode-rxlen-diag: patched %s @0x%x  0D06 or spr00c,0x0,r33 -> "
      "add spr00c,0x80,r33 (RxFrameSize +128)" % (path, off))
PY
