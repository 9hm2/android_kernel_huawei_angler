#!/usr/bin/env bash
# Guard the nexmon BCM4358 RX monitor path against a short-frame underflow.
#
# wl_monitor_radiotap() in
#   patches/bcm4358/<fwver>/nexmon/src/monitormode.c
# unconditionally strips 6 bytes from the received frame:
#
#     memcpy(p_new->data + ..., p->data + 6, p->len - 6);
#     p_new->len -= 6;
#
# p->len is the hardware-reported RX length. For a frame shorter than 6 bytes
# (corrupt/runt control frames, which appear under RX floods) "p->len - 6"
# underflows as unsigned to ~4 GiB, turning the memcpy into a massive
# out-of-bounds copy and faulting the firmware. The existing size check only
# bounds the new length from above (> 2032), not this lower bound.
#
# Add an early return for frames too short to strip 6 bytes from, before the
# allocation/copy. Idempotent.
#
# Usage: bcm4358-monitor-underflow-check.sh <path-to-monitormode.c>
set -euo pipefail

SRC="${1:?usage: $0 <monitormode.c>}"

if [ ! -f "$SRC" ]; then
	echo "::warning::monitor underflow-check: $SRC not found, skipping"
	exit 0
fi

if grep -q "short-frame underflow guard" "$SRC"; then
	echo "monitor underflow-check already present in $SRC, nothing to do"
	exit 0
fi

python3 - "$SRC" <<'PY'
import re, sys

path = sys.argv[1]
with open(path) as f:
    src = f.read()

# Insert the guard at the very start of wl_monitor_radiotap()'s body, right
# after the opening brace and variable declarations, before p->len is used.
# Anchor on the function signature + opening brace.
sig = ("void\n"
       "wl_monitor_radiotap(struct wl_info *wl, struct wl_rxsts *sts, "
       "struct sk_buff *p, unsigned char tunnel_over_udp)\n"
       "{\n")
if sig not in src:
    sys.stderr.write("monitor underflow-check: function signature not found; "
                     "firmware source layout may have changed\n")
    sys.exit(1)

guard = (
    sig +
    "    // short-frame underflow guard: the body strips 6 bytes via\n"
    "    // (p->len - 6); for a runt frame (< 6 bytes) this underflows as\n"
    "    // unsigned and turns the later memcpy into an out-of-bounds copy.\n"
    "    if (p->len < 6) {\n"
    "        return;\n"
    "    }\n"
)

src = src.replace(sig, guard, 1)

with open(path, "w") as f:
    f.write(src)
print(f"monitor underflow-check: added short-frame guard to {path}")
PY
