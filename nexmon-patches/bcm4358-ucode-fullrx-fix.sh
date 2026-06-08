#!/usr/bin/env bash
# THE FIX (clean, RE'd): deliver the FULL unprotected foreign DATA frame (WPA2
# EAPOL incl. Key MIC) to the host monitor on the BCM4358 d11, without touching
# the shared CCMP cipher path (so protected RX stays byte-identical) and without
# regressing management frames.
#
# Mechanism: unprotected (no-decrypt) frames reach the shared landing 0x0B85 via
# 0x0B1E (rxhdr bit14==0). The body-copy DMA kick is 0x0B98 (spr260=0x7), gated
# at 0x0B95 by [0x841] bit0. On the plaintext path [0x841] bit0=0 and spr262/
# [0x86B] are unset, so the kick never fires -> only the ~86B header reaches the
# host. The earlier reroute through the shared cipher block (0AB1-0AB4) DID fire
# the kick but applied CCMP's +0xC IV skip (0AB2) to plaintext -> 12-byte
# misalignment / dropped frames, and it cannot be edited in place (shared with
# real CCMP RX).
#
# Clean fix (5 words; image size unchanged): gate the no-op slot 0x0B86 to DATA
# frames and run a correct, IV-free setup in dead microcode space (0x1431-0x1434,
# orphaned after a rets at 0x1430; no branch targets it), then rejoin at 0x0B87:
#   0B86: orx(no-op)        -> je r42,0x2 ->1431        (DATA-only gate; mgmt/non-DATA
#                                                        fall through to 0B87 unchanged)
#   1431: (dead)            -> orx 1,0,0x1,[0x841],[0x841]  ; [0x841] bit0=1 (open 0B95)
#   1432: (dead)            -> or  spr1e2,0x0,spr262        ; spr262=spr1e2 (NO +0xC IV skip)
#   1433: (dead)            -> add r26,0xE,[0x86B]          ; [0x86B]=full length
#   1434: (dead)            -> jext 0x7F ->0B87             ; rejoin shared path
# spr1e0 already has bit6 (0x50) at 0B85, so no spr1e0 write is needed. The kick
# 0B96 spr261=[0x86B]-spr262=(r26+0xE)-spr1e2 is then correct (>0xE) and the body
# streams contiguously: LLC/SNAP aa aa 03 00 00 00 88 8e + full EAPOL.
# Protected RX: 0AAE/0AB1-0AB4/0B85 byte-identical (reaches 0B87 via 0B84,
# skipping 0B86). Management (r42!=2): 0B86 falls through to 0B87, kick gate stays
# closed -> byte-identical.
#
# Usage: bcm4358-ucode-fullrx-fix.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-fullrx: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
patches = [
    ("41280801e0810100", "315400ab5e680000", "0B86 -> je r42,0x2 ->1431 (DATA-only gate)"),
    ("8017009705b00000", "4128080560880100", "1431 set [0x841] bit0=1"),
    ("53342c005e680000", "6212008b47b00000", "1432 spr262=spr1e2 (no IV skip)"),
    ("1211000360bc0100", "6bc8016b5ee00000", "1433 [0x86B]=r26+0xE (full length)"),
    ("1511000360bc0100", "870b000080bf0300", "1434 jext 0x7F ->0B87 (rejoin)"),
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
