#!/usr/bin/env bash
# bcm4358-eapol-monitor-fullframe.sh — deliver full-length EAPOL to the
# monitor interface on the BCM4358 (fixes the 90-byte handshake truncation).
#
# Root cause (proven by RE of the RAM blob + on-device probes; see
# nexmon-patches/EAPOL-TRUNCATION-RE.md):
#
#   Captured WPA2 EAPOL-Key frames were truncated to a fixed 90 on-air bytes
#   (M2 MIC and M3 GTK lost -> handshake uncrackable). The census probe proved
#   the cut is EAPOL-specific (encrypted data reaches the monitor full to
#   1904B). The monitor-mode RX path is taken when wlc->monitor != 0
#   (e.g. 0x1a320e: ldr r3,[r5,#0x208]; cbnz -> 0x1a32ea). Inside that monitor
#   branch there is an EAPOL special-case:
#
#     0x1a3354  ldr  r1,[sp,#0x10]    ; r1 = frame ethertype
#     0x1a3356  movw r3,#0x888e       ; EAPOL ethertype
#     0x1a335a  cmp  r1,r3
#     0x1a335c  beq  0x1a3366         ; EAPOL -> special handler (ROM 0x23d68)
#     0x1a335e  movw r3,#0x88b4       ; (other ethertype)
#     0x1a3362  cmp  r1,r3
#     0x1a3364  bne  0x1a3376         ; neither -> normal FULL monitor delivery
#     0x1a3366  ... bl 0x23d68        ; the EAPOL special path that emits the
#                                       fixed ~96-byte stub the monitor clones
#
#   The 0x23d68 handler is in ROM (< 0x180000) and not patchable, but we don't
#   need it: we only have to stop EAPOL from entering it. Rewriting the 4-byte
#   `movw r3,#0x888e` at 0x1a3356 to `movw r3,#0x0000` makes the EAPOL compare
#   never match, so EAPOL falls through (via the 0x88b4 bne) to the normal,
#   full-length monitor delivery at 0x1a3376 -- the same path encrypted data
#   already uses (proven to deliver up to 1904 bytes).
#
#   This whole branch only runs in monitor mode, so the phone's own WPA
#   supplicant (which receives EAPOL on the normal host path, not here) is
#   unaffected -- no separate monitor gate is needed.
#
#   The 0x88b4 special case is left intact; only EAPOL (0x888e) is redirected.
#
# Idempotent. Verifies the target is exactly `movw r3,#0x888e` before patching.
#
# Usage: bcm4358-eapol-monitor-fullframe.sh <fw_bcmdhd.bin>
set -euo pipefail

FW="${1:?usage: $0 <fw_bcmdhd.bin>}"
[ -f "$FW" ] || { echo "::warning::eapol-fullframe: $FW not found, skipping"; exit 0; }

python3 - "$FW" <<'PY'
import sys

RAMSTART = 0x180000
SITE     = 0x1a3356                       # movw r3,#0x888e
# Thumb-2 MOVW T3 encoding of `movw r3,#0x888e` (little-endian bytes):
ORIG     = bytes([0x48, 0xf6, 0x8e, 0x03])
# Same encoding with imm16 = 0x0000 -> `movw r3,#0`:
#   MOVW: 1111 0i10 0100 iiii 0 iii dddd iiiiiiii
#   imm16=0 -> f2 40 03 00
NEW      = bytes([0x40, 0xf2, 0x00, 0x03])

fw = sys.argv[1]
blob = bytearray(open(fw, "rb").read())
off = SITE - RAMSTART
cur = bytes(blob[off:off+4])

if cur == NEW:
    print("eapol-fullframe: already applied (movw r3,#0 at 0x%06x)" % SITE)
    sys.exit(0)

if cur != ORIG:
    print("::warning::eapol-fullframe: 0x%06x is not `movw r3,#0x888e` "
          "(found %s, expected %s); firmware layout changed, skipping to stay "
          "safe" % (SITE, cur.hex(), ORIG.hex()))
    sys.exit(0)

blob[off:off+4] = NEW
open(fw, "wb").write(blob)
print("eapol-fullframe: redirected EAPOL to the full monitor path at 0x%06x "
      "(movw r3,#0x888e -> movw r3,#0); handshakes now capture complete" % SITE)
PY
