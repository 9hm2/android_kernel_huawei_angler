#!/usr/bin/env bash
# DEFINITIVE ucode-efficacy PROBE (throwaway test firmware -- expect Wi-Fi to
# BREAK if it works). Eight RX-path ucode patches plus a spr223=64 cap on the
# "universal" RX-DMA descriptor (01C8/01CA) ALL produced zero on-device change
# (captured frames still up to ~891 bytes). Either the patched RAM-ucode is not
# loaded into the live d11 PSM, or none of those sites are on the executed path.
#
# This probe removes the ambiguity: it turns instruction 0x0001 (an
# unconditional `jext 0x7F ->0FF7` in the d11's very first init steps, executed
# on EVERY boot before anything else) into a self-loop `jext 0x7F ->0001`, which
# hangs the PSM immediately. The PSM then never signals "ucode ready", so:
#   * Wi-Fi FAILS to initialize (wlan0 won't come up / fw init error / dongle
#     trap in dmesg)  => the patched ucode IS loaded into the live d11. Ucode
#     patching works; the 86-byte truncation is simply not at any site tried
#     (it is elsewhere -- a different ucode region or outside the PSM image).
#   * Wi-Fi works perfectly / monitor capture unchanged  => the patched ucode is
#     NOT loaded. Stop patching ucode; fix the decompress-into-IMEM deployment
#     (or the truncation is in d11 ROM / ARM, not this image).
#
# Recovery: reflash any earlier working build's fw_bcmdhd.bin. Nothing persists.
#
# Usage: bcm4358-ucode-hang-probe.sh <ucode.bin | fw_bcmdhd.bin>
set -euo pipefail
F="${1:?usage: $0 <ucode.bin|fw_bcmdhd.bin>}"
[ -f "$F" ] || { echo "::warning::ucode-hang: $F not found, skipping"; exit 0; }

python3 - "$F" <<'PY'
import sys
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
old = bytes.fromhex("f70ff002debf0300")   # 0001: jext 0x7F ->0FF7
new = bytes.fromhex("0100f002debf0300")   # 0001: jext 0x7F ->0001 (self-loop)
n_old = d.count(old)
if n_old == 0 and d.count(new) >= 1:
    print("ucode-hang: %s already has the init self-loop" % path); sys.exit(0)
if n_old != 1:
    sys.stderr.write("ucode-hang: expected exactly 1 site in %s, found %d -- aborting\n"
                     % (path, n_old)); sys.exit(1)
off = d.find(old); d[off:off+8] = new
open(path, 'wb').write(d)
print("ucode-hang: patched %s @0x%x  0001 jext 0x7F ->0FF7 => ->0001 (PSM init self-loop)" % (path, off))
PY
