#!/usr/bin/env bash
# Patch the BCM4358 d11 PSM ucode so monitor mode delivers UNPROTECTED frames
# (the EAPOL handshake) at FULL length, not truncated at ~86 bytes.
#
# Root cause (RE'd from the arch-15 disassembly, EMULATOR-VALIDATED with d11-emu):
# the host-DMA copy-length is SHM rx-status word [0x840] bits[5..10]. It is
# written ONLY on the encrypted RX path (ucode 0x0B83: orx 5,5,r25,[0x840]); the
# unprotected/plaintext path (0x0B85/0x0B86) never sets it, so copylen stays 0
# and the copy stops at the header -> the ~86 on-air bytes, Key MIC/keydata lost.
#
# Fix: replace ucode idx 0x0B86 (orx 0,3,0x0,[0x841],[0x841], a no-op for length
# that just clears the already-clear decrypt flag) with a copy-length write that
# maxes the 6-bit field:  orx 5,5,0x3F,[0x840],[0x840].
#   old 8 bytes: 41 28 08 01 e0 81 01 00
#   new 8 bytes: 40 08 08 fd e0 aa 01 00
# Emulation: unprotected copylen 0x00 -> 0x3F (full); protected path (never runs
# 0B86) unchanged. The 8-byte signature is unique in both ucode.bin and
# fw_bcmdhd.bin, so we search-and-replace wherever it occurs -- robust to whether
# the build hands us the extracted ucode (idx*8 = 0x5C30) or the firmware image
# (0x8c9c0 + 0x5C30 = 0x925F0).
#
# Usage: bcm4358-ucode-eapol-fulllen.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail

F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-eapol: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
old = bytes.fromhex("41280801e0810100")   # orx 0,3,0x0,[0x841],[0x841]
new = bytes.fromhex("400808fde0aa0100")   # orx 5,5,0x3F,[0x840],[0x840]
n_old = d.count(old)
n_new = d.count(new)
if n_new >= 1 and n_old == 0:
    print("ucode-eapol: %s already patched (%d sites)" % (path, n_new)); sys.exit(0)
if n_old != 1:
    sys.stderr.write("ucode-eapol: expected exactly 1 unpatched site in %s, found "
                     "%d (and %d patched) -- aborting\n" % (path, n_old, n_new))
    sys.exit(1)
off = d.find(old)
d[off:off+8] = new
open(path, 'wb').write(d)
print("ucode-eapol: patched %s @0x%x  %s -> %s  (d11 idx 0x0B86: max the [0x840] "
      "DMA copy-length on the unprotected RX path)" % (path, off, old.hex(), new.hex()))
PY
