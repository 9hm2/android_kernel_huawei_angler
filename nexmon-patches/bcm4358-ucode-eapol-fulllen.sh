#!/usr/bin/env bash
# Patch the BCM4358 d11 PSM ucode so monitor mode delivers UNPROTECTED frames
# (the EAPOL handshake) at FULL length, not truncated at ~86 bytes.
#
# Root cause (RE'd from the arch-15 disassembly and EXECUTION-VALIDATED in the
# d11-emu interpreter): on RX the rate-dispatch (ucode 0x0A5A-0x0A72) computes the
# full on-air length from the PLCP/L-SIG into r26. Then at
#   0x0A7E:  srx 13,0,spr02b,0x0,r26    ; r26 = RcvLFIFOStatus[13:0]
# the ucode OVERWRITES r26 with the receive/decrypt-FIFO byte count. For an
# unprotected frame the decrypt is aborted at the EAPOL-Key nonce, so the FIFO
# reports only ~86 bytes; 0x0A7E adopts that as the frame length, which flows to
# WEP_PSDULEN -> [0x86B] -> DAGG_BYTESLEFT (the host copy count) -> the ~86-byte
# monitor frame. Encrypted frames stream whole, so the FIFO reports full length.
#
# (An earlier theory that SHM [0x840][5:10] was the copy length was WRONG: that
# field is RXS_SECKINDX, the security key index -- patching it did nothing.)
#
# Fix: neutralize the 0x0A7E overwrite so the full PLCP-derived length survives:
#   srx 13,0,spr02b,0x0,r26   ->   or r26,0x0,r26   (no-op)
#   old 8 bytes: 9a 17 00 af 40 68 01 00
#   new 8 bytes: 9a 17 00 6b 5e b0 00 00
# d11-emu execution proof (same on-air frame, FIFO reports 1490 enc / 86 unprot):
#   original : enc 1490, unprot 86   (bug)
#   patched  : enc 1490, unprot 1490 (fixed; encrypted path byte-identical)
# EAPOL 4-way frames are sent at legacy/OFDM basic rates, which this covers.
#
# The 8-byte signature is unique in both the extracted ucode (idx 0x0A7E ->
# 0x53F0) and the firmware image (0x8c9c0 + 0x53F0 = 0x91DB0), so we
# search-and-replace wherever it occurs.
#
# Usage: bcm4358-ucode-eapol-fulllen.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail

F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-eapol: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
old = bytes.fromhex("9a1700af40680100")   # srx 13,0,spr02b,0x0,r26
new = bytes.fromhex("9a17006b5eb00000")   # or  r26,0x0,r26  (no-op)
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
print("ucode-eapol: patched %s @0x%x  %s -> %s  (d11 idx 0x0A7E: drop the "
      "FIFO-length overwrite so the full PLCP length survives for unprotected RX)"
      % (path, off, old.hex(), new.hex()))
PY
