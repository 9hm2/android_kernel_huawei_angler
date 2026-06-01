#!/usr/bin/env bash
# bcm4358-wps-assert-defuse.sh — defuse the WPS state-machine assert that
# crashes the BCM4358 monitor firmware during a reaver/bully WPS attack.
#
# Root cause (found by reverse-engineering the RAM firmware blob):
#
#   The firmware has a deliberate panic/"die here" stub at 0x182170 that
#   loads a recognizable signature into the saved registers (r1=0x01010101,
#   r2=0x02020202, ... lr=0x0e0e0e0e), then faults (udiv 0/0 ; str r5,[0] ;
#   bx lr -> 0x0e0e0e0e). That is exactly the dongle trap seen under reaver:
#       Dongle trap type 0x1 @ epc 0x0e0e0e10 ... lr 0x0e0e0e0e
#
#   The panic is reached from a WPS state-machine handler (func @0x185194,
#   reached only via a pointer table -- an event handler) at 0x18554a:
#
#       0x18553e  cmp r3, #0x66       ; one "impossible" state -> b . (hang)
#       0x185544  cmp r3, #0x63
#       0x185546  bne 0x18566e        ; any other state -> graceful return
#       0x18554a  bl  0x182170        ; state 0x63 -> PANIC  <-- the bug
#       0x18554e  mov r0, r6          ; <-- author's release-path continuation
#       0x185550  b   0x185672        ;     (normal function epilogue/return)
#
#   This is an over-strict debug ASSERT on an unexpected-but-recoverable WPS
#   state that reaver's aggressive PIN retries provoke. The authors wrote it
#   as "bl panic; <continue>", so an NDEBUG/release build would elide the
#   call and fall straight through to the graceful return at 0x18554e. We do
#   exactly that: replace the 4-byte `bl 0x182170` with `nop.w`, so the
#   handler returns normally (r0 = r6) instead of killing the chip.
#
#   Only the WPS-path assert (0x18554a) is defused. The firmware's other
#   caller of the same panic (0x183bf0, a different/non-WPS path) is left
#   intact to avoid masking unrelated faults.
#
# Idempotent. Verifies the target really is `bl 0x182170` before patching.
#
# Usage: bcm4358-wps-assert-defuse.sh <fw_bcmdhd.bin>
set -euo pipefail

FW="${1:?usage: $0 <fw_bcmdhd.bin>}"
[ -f "$FW" ] || { echo "::warning::wps-assert: $FW not found, skipping"; exit 0; }

python3 - "$FW" <<'PY'
import sys, struct

RAMSTART = 0x180000
SITE     = 0x18554a          # the `bl 0x182170` to defuse
PANIC    = 0x182170          # expected branch target
NOPW     = bytes([0xAF, 0xF3, 0x00, 0x80])   # nop.w

fw = sys.argv[1]
blob = bytearray(open(fw, "rb").read())
off = SITE - RAMSTART

def decode_bl(b, pc):
    h1 = b[0] | (b[1] << 8)
    h2 = b[2] | (b[3] << 8)
    if (h1 & 0xF800) != 0xF000 or (h2 & 0xC000) != 0xC000:
        return None
    S = (h1 >> 10) & 1
    imm10 = h1 & 0x3FF
    J1 = (h2 >> 13) & 1
    J2 = (h2 >> 11) & 1
    imm11 = h2 & 0x7FF
    I1 = 1 ^ (J1 ^ S)
    I2 = 1 ^ (J2 ^ S)
    imm = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if imm & (1 << 24):
        imm -= (1 << 25)
    return pc + 4 + imm

cur = bytes(blob[off:off+4])

if cur == NOPW:
    print("wps-assert: already defused (nop.w at 0x%06x), nothing to do" % SITE)
    sys.exit(0)

tgt = decode_bl(cur, SITE)
if tgt is None or (tgt & ~1) != PANIC:
    print("::warning::wps-assert: 0x%06x is not `bl 0x%06x` (found bytes %s, "
          "target %s); firmware layout changed, skipping to stay safe"
          % (SITE, PANIC, cur.hex(),
             ("0x%06x" % (tgt & ~1)) if tgt is not None else "n/a"))
    sys.exit(0)

blob[off:off+4] = NOPW
open(fw, "wb").write(blob)
print("wps-assert: defused WPS state-machine panic at 0x%06x "
      "(bl 0x%06x -> nop.w); reaver/bully no longer crash the dongle" %
      (SITE, PANIC))
PY
