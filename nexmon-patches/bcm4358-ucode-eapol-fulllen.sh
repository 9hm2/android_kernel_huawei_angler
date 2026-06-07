#!/usr/bin/env bash
# Patch the BCM4358 d11 PSM ucode so monitor mode delivers UNPROTECTED frames
# (the EAPOL handshake) at FULL length, not truncated at the ~86-byte
# header-through-nonce boundary.
#
# Root cause (reverse-engineered from the disassembled ucode, arch 15): in the
# RX decrypt/cipher-offset routine (ucode 0x0B40-0x0B95), encrypted frames get a
# per-cipher copy-length extension (r25, packed into rx-status word [0x840]) and
# are DMA'd whole; the PLAINTEXT fall-through (0x0B85/0x0B86) instead switches the
# crypto ctrl to plaintext and CLEARS the decrypt-state bit ([0x841]), so no
# extension is applied and the copy stops at the header -> the measured ~90-byte
# lbuf (= 86 on-air) with the Key MIC/keydata tail never reaching RAM.
#
# Candidate A (minimal, 1 byte, reversible): at ucode idx 0x0B86
#   orx 0,3,0x0,[0x841],[0x841]   ->   orx 0,3,0x1,[0x841],[0x841]
# i.e. SET the [0x841] decrypt-state bit even on the plaintext path, so the
# full-copy handling is taken for unprotected frames too.
#
# The ucode lives uncompressed in the firmware at RAM 0x20c9c0 (file offset
# UCODESTART-RAMSTART = 0x8c9c0). idx 0x0B86 -> ucode byte 0x5C30 -> file byte
# 0x925F0; only byte 0x925F3 changes (0x01 -> 0x05). nexmon's build extracts this
# ucode (dd), recompresses and re-embeds it, so patching the firmware file here
# propagates into the built fw_bcmdhd.bin.
#
# Usage: bcm4358-ucode-eapol-fulllen.sh <path-to-nexmon-fw_bcmdhd.bin>
set -euo pipefail

FW="${1:?usage: $0 <fw_bcmdhd.bin>}"
[ -f "$FW" ] || { echo "::warning::ucode-eapol: $FW not found, skipping"; exit 0; }

PATCH_OFF=$((0x925F3))           # file offset of the byte to change
EXPECT_BLOCK_OFF=$((0x925F0))    # start of the 8-byte instruction

python3 - "$FW" "$PATCH_OFF" "$EXPECT_BLOCK_OFF" <<'PY'
import sys
fw, poff, boff = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
d = bytearray(open(fw, 'rb').read())
old8 = bytes(d[boff:boff+8])
want_old = bytes.fromhex("41280801e0810100")
want_new = bytes.fromhex("41280805e0810100")
if old8 == want_new:
    print("ucode-eapol: already patched, nothing to do"); sys.exit(0)
if old8 != want_old:
    sys.stderr.write("ucode-eapol: unexpected bytes at 0x%x: %s (want %s)\n"
                     % (boff, old8.hex(), want_old.hex()))
    sys.exit(1)
assert d[poff] == 0x01, "byte at patch offset is not 0x01"
d[poff] = 0x05
open(fw, 'wb').write(d)
print("ucode-eapol: patched %s @0x%x  0x01->0x05  (d11 ucode idx 0x0B86: "
      "set [0x841] decrypt bit on plaintext RX path -> full-length copy)" % (fw, poff))
PY
