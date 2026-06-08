#!/usr/bin/env bash
# THE FIX (RE'd root cause): the BCM4358 d11 copy/descrambler engine streams the
# RX PSDU body from the FIFO into host memory under spr1e0(enable)+spr064(source
# pointer)+spr1e3(length). For UNPROTECTED frames the RX path lands at 0x0B85
# (engine enabled, spr1e3=full length already set at 0x0A80) but NEVER sets
# spr064 -- the FIFO source pointer keeps a stale value, so the engine stalls
# after the ~86-byte header copy. Protected (e.g. CCMP) frames set spr064 at
# 0x0B65 and stream the whole body -> they arrive full. (Confirmed by the ROM
# debug string "wepctl.. wep_psdulen.. RXE_RXCNT.. DAGG.." and the CCMP path,
# which also skips [0x841].0 and the spr260=7 kick yet arrives full -- proving
# spr260=7 is NOT the body trigger, spr064 is.)
#
# Fix: write spr064 on the unprotected path by repurposing 0x0B86 -- a redundant
# [0x841] bit-clear on that path (bits 0/3 are already 0 there) that protected
# frames skip entirely (they jump 0B84->0B87). One 8-byte edit, reversible, and
# protected RX stays byte-identical.
#
# Variants (set UCODE_SPR064_VARIANT, default A):
#   A  0B86 = add [0x2B],spr1e2,spr064   ; source = FIFO base + MAC-hdr offset
#                                          (no security header for plaintext)
#   C  0B86 = add [0x2B],0x0,spr064      ; source = FIFO frame base (always
#                                          aligned; streams whole frame, header
#                                          may be duplicated -- robustness probe)
#   B  0AAE ->0AB1 (run shared 0AB1-0AB3 so spr262 is valid) AND
#      0B86 = add [0x2B],spr262,spr064   ; source = where the header pull stopped
#
# On-device reading: full 802.11 frame with a real EAPOL Key MIC = solved;
# longer frame but body shifted/garbled = right knob, wrong offset (try B/C);
# no change = spr064 not the source on this build; no capture = bad FIFO source
# (revert). The 8-byte signatures are unique in both the extracted ucode and the
# firmware image, so we search-and-replace wherever they occur.
#
# Usage: bcm4358-ucode-spr064-fix.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-spr064: $F not found, skipping"; exit 0; }
VARIANT="${UCODE_SPR064_VARIANT:-A}"

python3 - "$F" "$VARIANT" <<'PY'
import sys
path, variant = sys.argv[1], sys.argv[2].upper()
d = bytearray(open(path, 'rb').read())

OLD_0B86 = "41280801e0810100"   # orx 0,3,0x0,[0x841],[0x841]  (redundant on unprot path)
OLD_0AAE = "b50a0013c9030200"   # jzx 0,7,spr244 ->0AB5
# per-variant edits: list of (old_hex, new_hex, label)
VAR = {
    "A": [(OLD_0B86, "64503cae00e00000", "0B86 add [0x2B],spr1e2,spr064")],
    "C": [(OLD_0B86, "641000af00e00000", "0B86 add [0x2B],0x0,spr064")],
    "B": [(OLD_0AAE, "b10a0013c9030200", "0AAE jzx spr244 ->0AB1 (run 0AB1-0AB3)"),
          (OLD_0B86, "64504cae00e00000", "0B86 add [0x2B],spr262,spr064")],
}
if variant not in VAR:
    sys.exit("ucode-spr064: unknown variant %r (want A/B/C)" % variant)

# guard: a different variant's 0B86 add must not already be present
others = {"A":"64503cae00e00000","C":"641000af00e00000","B":"64504cae00e00000"}
for v,h in others.items():
    if v != variant and bytes.fromhex(h) in d:
        sys.exit("ucode-spr064: %s already carries variant %s 0B86 -- aborting" % (path, v))

done = 0
for old_h, new_h, label in VAR[variant]:
    old, new = bytes.fromhex(old_h), bytes.fromhex(new_h)
    n_old, n_new = d.count(old), d.count(new)
    if n_new >= 1 and n_old == 0:
        print("ucode-spr064[%s]: %s already patched [%s]" % (variant, path, label)); done += 1; continue
    if n_old != 1:
        sys.stderr.write("ucode-spr064[%s]: expected exactly 1 site for %s in %s, found "
                         "%d (and %d patched) -- aborting\n" % (variant, label, path, n_old, n_new))
        sys.exit(1)
    off = d.find(old); d[off:off+8] = new
    print("ucode-spr064[%s]: patched %s @0x%x  %s" % (variant, path, off, label)); done += 1
if done == len(VAR[variant]):
    open(path, 'wb').write(d)
PY
