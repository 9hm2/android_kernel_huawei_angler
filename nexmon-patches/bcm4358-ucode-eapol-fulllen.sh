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
# Fix (emulator-validated, d11-emu trace): at ucode idx 0x0B86, write the
#   [0x840] DMA copy-length field to max on the unprotected path:
#   orx 0,3,0x0,[0x841],[0x841]  ->  orx 5,5,0x3F,[0x840],[0x840]
# Candidates that only set the [0x841] decrypt bit do NOT work (copylen stays 0).
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

EXPECT_BLOCK_OFF=$((0x925F0))    # start of the 8-byte instruction (idx 0x0B86)

# Emulator-validated fix (d11-emu trace): the host-DMA copy-length is SHM
# rx-status word [0x840] bits[5..10], written ONLY on the encrypted path
# (0B66/0B83: orx 5,5,r25,[0x840]). The unprotected path (0B85/0B86) never sets
# it, so copylen stays 0 -> truncated. Replace 0B86's no-op-for-length
# (orx 0,3,0x0,[0x841],[0x841], which only clears the already-clear decrypt
# flag) with a copy-length write that sets the 6-bit field to max:
#   orx 5,5,0x3F,[0x840],[0x840]
# Verified in emulation: unprotected copylen 0x00 -> 0x3F (full); protected
# path (never executes 0B86) unchanged at 0x13. Neighbors 0B84/0B85/0B87 intact.
python3 - "$FW" "$EXPECT_BLOCK_OFF" <<'PY'
import sys
fw, boff = sys.argv[1], int(sys.argv[2])
d = bytearray(open(fw, 'rb').read())
old8 = bytes(d[boff:boff+8])
want_old = bytes.fromhex("41280801e0810100")  # orx 0,3,0x0,[0x841],[0x841]
want_new = bytes.fromhex("400808fde0aa0100")  # orx 5,5,0x3F,[0x840],[0x840]
if old8 == want_new:
    print("ucode-eapol: already patched, nothing to do"); sys.exit(0)
if old8 != want_old:
    sys.stderr.write("ucode-eapol: unexpected bytes at 0x%x: %s (want %s)\n"
                     % (boff, old8.hex(), want_old.hex()))
    sys.exit(1)
d[boff:boff+8] = want_new
open(fw, 'wb').write(d)
print("ucode-eapol: patched %s @0x%x  %s -> %s  (d11 idx 0x0B86: set the "
      "[0x840] DMA copy-length field to max on the unprotected RX path -> "
      "full-length EAPOL)" % (fw, boff, want_old.hex(), want_new.hex()))
PY
