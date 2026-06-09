#!/usr/bin/env bash
# FORCE-DECRYPT ucode patch: route the foreign AP's UNPROTECTED frames (the WPA2
# EAPOL) through the d11 WEP-decrypt block so the cipher engine DRAINS the full
# body into readable staging/host lbuf (XOR'd with a keystream we can recompute),
# then the ARM XORs it back to recover the plaintext Nonce+MIC.
#
# Why this works (datapath-proven): on the decrypt path the body host-DMA KICK#2
# (0CE3) fires UNCONDITIONALLY before the ICV/MIC check (0CF1/0CF2 only set the
# RXS_DECERR flag afterward) -- a failing WEP ICV still delivers the body. And our
# diag HookPatch sits at 0x1a6cfc, BEFORE the firmware's 0x310 (incl DECERR bit4)
# drop, so we capture the delivered (XOR'd) frame even though it is later dropped.
#
# TA-gated: 0B1E (the Protected->plaintext divert) is replaced to send only frames
# whose AMT Addr2 match == our slot 0 into the crypto block; protected frames and
# all other unprotected frames reach their identical stock destinations. Pair with
# the runtime ARM key-table programming (ioctl 0x610) that puts the AP's A2 in AMT
# slot 0 + a WEP key in key slot 0.
#
# 5 words, all verified vs ucode_real.bin and re-decoded with d11dasm (the two
# unconditional jumps use the proven-safe `je r0,r0 ->target` form, NOT jext):
#   0B1E je r0,r0 ->1431
#   1431 srx 5,0,spr275 ->r33          ; r33 = Addr2(TA) AMT match index
#   1432 jnzx 0,14,[0x03,off1] ->0B1F  ; Protected=1 -> normal crypto (stock)
#   1433 je r33,0x0 ->0B1F             ; unprotected + our AMT slot 0 -> FORCE decrypt
#   1434 je r0,r0 ->0B85               ; unprotected + other slot -> stock plaintext divert
#
# ALGO-FORCE (5 more words): routing an unprotected frame into 0B1F is not enough --
# the cipher algo is re-read from the keyidx/algo SHM word at 0B5F (r38), which is 0
# (OPEN) for an unprotected frame, so 0B67 leaves the WEP engine IDLE (no decrypt, no
# body drain). These words force r38=WEP1 for ONLY the forced (unprotected) frame, so
# the engine actually runs. Gated by the FC.Protected bit so real protected frames
# (which also flow through 0B60) are untouched; the displaced stock 0B60 test is
# replicated at 1437. (Whether the engine running also lengthens the host body-DMA is
# the open question this build tests: the body-drain length is built at 0E76 from
# spr041, a hw decrypt-state reg -- if it is write-then-flag, plen grows; if it is
# key-match-gated, plen stays 96. One on-device capture decides it.)
#   0B60 je r0,r0 ->1435               ; (was: jne r38,0x7 ->0B64) divert into algo stub
#   1435 jnzx 0,14,[0x03,off1] ->1437  ; Protected=1 -> skip force (stock behaviour)
#   1436 orx 7,8,0x0,0x1,r38           ; unprotected forced frame -> r38 = WEP1
#   1437 jne r38,0x7 ->0B64            ; replicate the displaced stock 0B60
#   1438 je r0,r0 ->0B61               ; rejoin the validate/keyptr flow
#
# Usage: bcm4358-ucode-forcedecrypt.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-forcedecrypt: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
UCODE_BASE_IN_FW = 0x8c9c0
base = 0 if len(d) < 0x20000 else UCODE_BASE_IN_FW
patches = [
    (0x0B1E, "850b000f52070200", "3114f0025e680000", "0B1E je r0,r0 ->1431 (enter TA-gate stub)"),
    (0x1431, "8017009705b00000", "a11700d749280100", "1431 r33 = spr275 AMT Addr2 match index"),
    (0x1432, "53342c005e680000", "1f0b000f52870200", "1432 jnzx [0x03,off1] bit14 ->0B1F (protected=normal)"),
    (0x1433, "1211000360bc0100", "1f0b00875e680000", "1433 je r33,0x0 ->0B1F (unprot + our slot -> FORCE)"),
    (0x1434, "1511000360bc0100", "850bf0025e680000", "1434 je r0,r0 ->0B85 (unprot + other -> stock divert)"),
    # --- algo-force: make the WEP engine actually RUN on the forced frame ---
    (0x0B60, "64eb009bde680000", "3514f0025e680000", "0B60 je r0,r0 ->1435 (divert into algo-force stub)"),
    (0x1435, "6410009b05b00000", "3714000f52870200", "1435 jnzx 0,14,[0x03,off1] ->1437 (protected -> skip force)"),
    (0x1436, "3e14002345000200", "a637000360bc0100", "1436 orx 7,8,0x0,0x1,r38 (force r38 = WEP1)"),
    (0x1437, "8117001f45b00000", "64eb009bde680000", "1437 jne r38,0x7 ->0B64 (replicate displaced 0B60)"),
    (0x1438, "8037f09205e80000", "610bf0025e680000", "1438 je r0,r0 ->0B61 (rejoin validate)"),
]
if bytes(d[base:base+8]) != bytes.fromhex("4e10000360bc0100"):
    sys.stderr.write("ucode-forcedecrypt: anchor not at base 0x%x in %s -- aborting\n" % (base, path)); sys.exit(1)
for idx, old_h, new_h, label in patches:
    off = base + idx * 8
    cur = bytes(d[off:off+8])
    if cur == bytes.fromhex(new_h):
        print("ucode-forcedecrypt: %s @0x%x already patched [%s]" % (path, off, label)); continue
    if cur != bytes.fromhex(old_h):
        sys.stderr.write("ucode-forcedecrypt: %s @0x%x expected %s got %s [%s] -- aborting\n"
                         % (path, off, old_h, cur.hex(), label)); sys.exit(1)
    d[off:off+8] = bytes.fromhex(new_h)
    print("ucode-forcedecrypt: patched %s @0x%x  %s" % (path, off, label))
open(path, 'wb').write(d)
PY
