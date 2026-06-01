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
#   The panic is reached from two RAM-resident debug asserts on the WPS
#   association path, each a conditional `bl panic` immediately followed by
#   the author's normal (release) continuation:
#
#     0x18554a  WPS state-machine handler (func @0x185194, pointer-table only):
#       0x185544  cmp r3, #0x63
#       0x185546  bne 0x18566e       ; other states -> graceful return
#       0x18554a  bl  0x182170       ; state 0x63 -> PANIC  <-- bug
#       0x18554e  mov r0,r6 ; b 0x185672   ; release-path graceful return
#
#     0x183bf0  WPS assoc path:
#       0x183bee  bpl 0x183bf4       ; normal case already SKIPS the panic
#       0x183bf0  bl  0x182170       ; asserted case -> PANIC  <-- bug
#       0x183bf4  ands r5,#2 ; ...   ; the normal continuation (bpl target)
#
#   Both are over-strict debug ASSERTs on unexpected-but-recoverable WPS
#   states that reaver's/bully's aggressive PIN retries provoke. Written as
#   "bl panic; <continue>", an NDEBUG/release build would elide the calls and
#   fall straight through to the working continuation. We do exactly that:
#   replace each 4-byte `bl 0x182170` with `nop.w`. (Defusing only 0x18554a
#   first just moved the crash onto 0x183bf0 with a new call chain -- both are
#   on the WPS path, so both must go.)
#
# Idempotent. Verifies each target really is `bl 0x182170` before patching;
# skips any site whose bytes don't match (safe if the firmware layout shifts).
#
# Usage: bcm4358-wps-assert-defuse.sh <fw_bcmdhd.bin>
set -euo pipefail

FW="${1:?usage: $0 <fw_bcmdhd.bin>}"
[ -f "$FW" ] || { echo "::warning::wps-assert: $FW not found, skipping"; exit 0; }

python3 - "$FW" <<'PY'
import sys

RAMSTART = 0x180000
PANIC    = 0x182170          # the panic/"die here" stub entry
NOPW     = bytes([0xAF, 0xF3, 0x00, 0x80])   # nop.w

# Both `bl 0x182170` sites that the reaver/WPS path reaches. Each is a
# conditional debug assert immediately followed by the author's normal
# (release) continuation, so eliding the call (nop.w) falls straight through
# to working code -- exactly what an NDEBUG build does:
#   0x18554a  WPS state-machine handler: ... b 0x185672 (graceful return)
#   0x183bf0  WPS assoc path: bpl 0x183bf4 already skips it; fall-through is
#             the normal `ands r5,#2; ...` continuation.
SITES = (0x18554a, 0x183bf0)

fw = sys.argv[1]
blob = bytearray(open(fw, "rb").read())

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

changed = False
for site in SITES:
    off = site - RAMSTART
    cur = bytes(blob[off:off+4])
    if cur == NOPW:
        print("wps-assert: 0x%06x already defused (nop.w)" % site)
        continue
    tgt = decode_bl(cur, site)
    if tgt is None or (tgt & ~1) != PANIC:
        print("::warning::wps-assert: 0x%06x is not `bl 0x%06x` (bytes %s, "
              "target %s); layout changed, skipping this site to stay safe"
              % (site, PANIC, cur.hex(),
                 ("0x%06x" % (tgt & ~1)) if tgt is not None else "n/a"))
        continue
    blob[off:off+4] = NOPW
    changed = True
    print("wps-assert: defused panic at 0x%06x (bl 0x%06x -> nop.w)"
          % (site, PANIC))

if changed:
    open(fw, "wb").write(blob)
    print("wps-assert: reaver/bully WPS attacks no longer crash the dongle")
else:
    print("wps-assert: nothing to do")
PY
