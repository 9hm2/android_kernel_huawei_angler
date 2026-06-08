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
# THE BUG in the prior attempt: [0x841] bit0 is RXS_AMSDU_MASK. Setting it to
# pass the 0B95 kick gate marked plaintext DATA frames as A-MSDU, so the host's
# wlc_recvdata tried to de-aggregate a plain EAPOL frame and DROPPED it (mgmt
# never sets AMSDU -> survived). Fix: arm the full body copy (spr260=0x7)
# DIRECTLY without ever touching [0x841] (no AMSDU), so the frame is delivered
# intact. spr262/[0x86B] are stale on the plaintext path (0AB2/0AB3 + the
# 0B1F-0B81 descriptor block are skipped via 0AAE->0AB5 / 0B1E->0B85), so set
# them explicitly with NO IV skip.
#
# Clean fix (6 words; image size unchanged): gate the no-op slot 0x0B86 to DATA
# frames and run an IV-free setup that arms the body copy DIRECTLY in dead
# microcode space (0x1431-0x1435, orphaned after a rets at 0x1430; no branch
# targets it), then resume at 0x0B87:
#   0B86: orx(no-op) -> je r42,0x2 ->1431   (DATA-only gate; mgmt/non-DATA fall
#                                            through to 0B87 unchanged)
#   1431: -> or  spr1e2,0x0,spr262          ; spr262=spr1e2 (NO +0xC IV skip)
#   1432: -> add r26,0xE,[0x86B]            ; [0x86B]=full length
#   1433: -> sub [0x86B],spr262,spr261      ; spr261=body length
#   1434: -> orx 7,8,0,7,spr260             ; arm full body copy (NO AMSDU bit)
#   1435: -> jext 0x7F ->0B87               ; resume normal DATA finalization
# [0x841] is NEVER written, so bit0 (RXS_AMSDU) stays 0 -> host does not
# de-aggregate -> EAPOL delivered intact. spr1e0 already has bit6 (0x50) at 0B85.
# Protected RX: 0AAE/0AB1-0AB4/0B85 byte-identical (reaches 0B87 via 0B84,
# skipping 0B86). Management (r42!=2): 0B86 falls through to 0B87, no copy armed
# -> byte-identical.
#
# Usage: bcm4358-ucode-fullrx-fix.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-fullrx: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
# Patch by exact instruction INDEX (the dead-space words are not byte-unique, so
# search-replace cannot be used). The ucode lives at offset 0 in the extracted
# ucode.bin, and at UCODESTART-RAMSTART = 0x8c9c0 in the firmware image.
UCODE_BASE_IN_FW = 0x8c9c0
base = 0 if len(d) < 0x20000 else UCODE_BASE_IN_FW
# (instr_index, old_hex, new_hex, label)
patches = [
    (0x0B86, "41280801e0810100", "315400ab5e680000", "0B86 -> je r42,0x2 ->1431 (DATA-only gate)"),
    (0x1431, "8017009705b00000", "4128080d60900100", "1431 set [0x841] bits[1:0]=3 (like protected 0AB1)"),
    (0x1432, "53342c005e680000", "6212008b47b00000", "1432 spr262=spr1e2 (no IV skip)"),
    (0x1433, "1211000360bc0100", "6bc8016b5ee00000", "1433 [0x86B]=r26+0xE (full length)"),
    (0x1434, "1511000360bc0100", "870b000080bf0300", "1434 jext 0x7F ->0B87 (kick via 0B95-0B98)"),
]
# anchor sanity: ucode[0] must be the known first instruction
if bytes(d[base:base+8]) != bytes.fromhex("4e10000360bc0100"):
    sys.stderr.write("ucode-fullrx: ucode anchor not at base 0x%x in %s -- aborting\n" % (base, path))
    sys.exit(1)
for idx, old_h, new_h, label in patches:
    off = base + idx * 8
    cur = bytes(d[off:off+8])
    if cur == bytes.fromhex(new_h):
        print("ucode-fullrx: %s @0x%x already patched [%s]" % (path, off, label)); continue
    if cur != bytes.fromhex(old_h):
        sys.stderr.write("ucode-fullrx: %s @0x%x expected %s got %s [%s] -- aborting\n"
                         % (path, off, old_h, cur.hex(), label)); sys.exit(1)
    d[off:off+8] = bytes.fromhex(new_h)
    print("ucode-fullrx: patched %s @0x%x  %s" % (path, off, label))
open(path, 'wb').write(d)
PY
