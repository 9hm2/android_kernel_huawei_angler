#!/usr/bin/env bash
# Patch the BCM4358 d11 PSM ucode so monitor mode delivers UNPROTECTED frames
# (the EAPOL handshake) at FULL length, not truncated at ~86 bytes.
#
# Mechanism (RE'd from the arch-15 disassembly; the full frame IS in the RX FIFO
# -- RxFrameSize is full for both paths -- so this is a software copy decision):
# the cipher-key test at 0x0AAE gates BOTH the full-length store and the bulk
# payload copy:
#   0AAE: jzx 0,7,spr244 -> 0AB5   ; spr244 bit7 = cipher key present
#         plaintext (no key) jumps to 0AB5, SKIPPING:
#           0AB1 ([0x841]bit0 = decrypt/full-copy flag)
#           0AB3 ([0x86B] = r26+14 = FULL frame length)
#   0B95: jzx 0,0,[0x841] -> 0B99  ; with bit0=0 (plaintext) jumps over the bulk
#         DAGG kick 0B96-0B98 (spr261=[0x86B]-spr262, spr260=7 = full payload copy)
# Net: plaintext runs only the ~86B header DAGG; the full-length store and the
# bulk-payload copy are both branched around -> header-through-nonce truncation.
# (This is why prior length/timing patches at 0A7E/copy-loop did nothing: plaintext
# never executes the length-store or bulk-copy kick at all.)
#
# Fix: route plaintext into the encrypted FULL-COPY path WITHOUT starting decrypt,
# via two 1-byte branch-target redirects:
#   0AAE: ...->0AB5  =>  ...->0AB2   (run 0AB2/0AB3/0AB4: set [0x86B] full, skip
#                                     0AB1 so no decrypt engine is started)
#   0B95: ...->0B99  =>  ...->0B96   (run 0B96/0B97/0B98: bulk DAGG full copy)
# Encrypted path is byte-identical (both edits only move plaintext-taken edges).
# 2 bytes total, reversible. Covers legacy/OFDM EAPOL rates.
#
# The 8-byte signatures are unique in both the extracted ucode (idx*8) and the
# firmware image (0x8c9c0 + idx*8), so we search-and-replace wherever they occur.
#
# Usage: bcm4358-ucode-eapol-fulllen.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail

F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-eapol: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
# (old, new, label) -- each redirects a plaintext-only branch into the full-copy path
patches = [
    ("b50a0013c9030200", "b20a0013c9030200", "0AAE jzx spr244 ->0AB5=>0AB2 (full-len store)"),
    ("990b000721000200", "960b000721000200", "0B95 jzx [0x841] ->0B99=>0B96 (bulk DAGG copy)"),
]
done = 0
for old_h, new_h, label in patches:
    old = bytes.fromhex(old_h); new = bytes.fromhex(new_h)
    n_old, n_new = d.count(old), d.count(new)
    if n_new >= 1 and n_old == 0:
        print("ucode-eapol: %s already patched [%s]" % (path, label)); done += 1; continue
    if n_old != 1:
        sys.stderr.write("ucode-eapol: expected exactly 1 site for %s in %s, found "
                         "%d (and %d patched) -- aborting\n" % (label, path, n_old, n_new))
        sys.exit(1)
    off = d.find(old); d[off:off+8] = new
    print("ucode-eapol: patched %s @0x%x  %s -> %s  [%s]"
          % (path, off, old_h, new_h, label)); done += 1
if done == len(patches):
    open(path, 'wb').write(d)
PY
