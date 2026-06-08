#!/usr/bin/env bash
# THE FIX (RE'd): make the BCM4358 d11 deliver the FULL frame to the host for
# UNPROTECTED foreign DATA frames in monitor mode (so the WPA2 EAPOL Key MIC is
# captured), instead of only a ~92-byte header lookahead.
#
# Root cause: the RX classifier gate 0x0B1E (jzx 0,14,[0x03,off1]) tests bit14 of
# the hardware rxhdr ("frame will be decrypted"). Unprotected/non-decryptable
# DATA frames (bit14=0) jump to 0x0B85, the header-only landing, which sets
#   0B85: orx 4,4,0x15,0x0,spr1e0   ; spr1e0 = 0x50  -- bit6 (PSDU-body-stream
#                                                       to host) CLEARED
# so the RXE copy engine never streams the PSDU body; only the lookahead header
# reaches the host lbuf. Protected/management frames take the decrypt/copy path
# (0B1E falls through .. 0B84 jext ->0B87, skipping 0B85) and keep bit6 set, so
# they arrive full. (This is upstream of the spr223 DMA byte-count at 0x01C8 --
# which is why forcing spr223 small did nothing: only ~92 bytes were ever in the
# FIFO.) An ARM-only/SHM fix is impossible: the gate reads the hardware rxhdr,
# and the full bytes are not in the lbuf -- only the d11 can deliver them.
#
# Fix: at 0x0B85 set spr1e0 bit6 (stream the body) for the header-only landing:
#   orx 4,4,0x15,0x0,spr1e0  (0x50) -> orx 4,4,0x1D,0x0,spr1e0  (0xD0)
# i.e. ONE byte: file offset 0x5C2B 0x57 -> 0x77. 0xD0 is the exact value the
# ucode already uses at 0x0A8A for normal non-encrypted full RX (known good).
# Protected RX never executes 0B85 -> byte-identical. 0B86 (clears the host
# "decrypted" status bit) is untouched -> plaintext stays correctly marked.
#
# Usage: bcm4358-ucode-fullrx-fix.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-fullrx: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
# Two edits make the no-key (unprotected) RX path actually fire the body-copy
# DMA kick (0B98 spr260=0x7), which is gated at 0B95 by [0x841] bit0:
#   (1) 0AAE jzx spr244 ->0AB5  =>  ->0AB1 : run the setup block 0AB1-0AB4 on the
#       no-key path so [0x841] bit0=1 (unblocks 0B95), spr262 + [0x86B] are set.
#   (2) 0B85 orx 4,4,0x15->0x1D : keep spr1e0 bit6 (PSDU-body-stream-to-host) set
#       on the header-only landing (0xD0 = the value 0x0A8A already uses for
#       normal non-encrypted full RX).
# Protected/mgmt-with-key RX is byte-identical (0AAE only branches when no key).
patches = [
    ("b50a0013c9030200", "b10a0013c9030200", "0AAE jzx spr244 ->0AB5 => ->0AB1 (run setup, set [0x841].0)"),
    ("e011005760a20100", "e011007760a20100", "0B85 spr1e0 0x50->0xD0 (body-stream bit6)"),
]
done = 0
for old_h, new_h, label in patches:
    old, new = bytes.fromhex(old_h), bytes.fromhex(new_h)
    n_old, n_new = d.count(old), d.count(new)
    if n_new >= 1 and n_old == 0:
        print("ucode-fullrx: %s already patched [%s]" % (path, label)); done += 1; continue
    if n_old != 1:
        sys.stderr.write("ucode-fullrx: expected exactly 1 site for %s in %s, found %d "
                         "(and %d patched) -- aborting\n" % (label, path, n_old, n_new)); sys.exit(1)
    off = d.find(old); d[off:off+8] = new
    print("ucode-fullrx: patched %s @0x%x  %s" % (path, off, label)); done += 1
if done == len(patches):
    open(path, 'wb').write(d)
PY
