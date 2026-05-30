#!/usr/bin/env bash
# Harden the nexmon BCM4358 frame-injection handler against SKB-pool
# exhaustion.
#
# The NEX_INJECT_FRAME ioctl handler in
#   patches/bcm4358/<fwver>/nexmon/src/ioctl.c
# calls pkt_buf_get_skb() in a loop but never checks the result. Under a
# sustained injection flood that also hops channels (mdk3 d -c, aireplay -9
# across targets) the firmware SKB pool runs dry, pkt_buf_get_skb() returns
# NULL, and the following skb_pull(NULL, 202) faults inside the firmware:
#
#   Dongle trap type 0x4 @ epc 0x216dfc
#
# which tears the dongle down (PCIe link down -> endless devreset/recovery).
#
# Newer nexmon chip patches (e.g. bcm4375b1) already guard this with
# "if (p == 0) break;". This script back-ports the same guard to the BCM4358
# handler that lacks it. It is idempotent: if the guard is already present it
# does nothing.
#
# Usage: bcm4358-inject-null-check.sh <path-to-nexmon-src-ioctl.c>
set -euo pipefail

IOCTL="${1:?usage: $0 <ioctl.c>}"

if [ ! -f "$IOCTL" ]; then
	echo "::warning::inject NULL-check patch: $IOCTL not found, skipping"
	exit 0
fi

if grep -q "if (p == 0)" "$IOCTL"; then
	echo "inject NULL-check already present in $IOCTL, nothing to do"
	exit 0
fi

# Insert "if (p == 0) break;" after each unchecked pkt_buf_get_skb()/skb_pull
# pair in the NEX_INJECT_FRAME handler. Both branches use the pattern:
#     p = pkt_buf_get_skb(wlc->osh, ...);
#     skb_pull(p, 202);
# We add the guard between those two lines.
python3 - "$IOCTL" <<'PY'
import re, sys

path = sys.argv[1]
with open(path) as f:
    src = f.read()

# Match: p = pkt_buf_get_skb(...);  (capturing indentation) followed by
# the next line skb_pull(p, 202);  and inject the NULL guard in between.
pattern = re.compile(
    r"(?P<indent>[ \t]*)(?P<get>p = pkt_buf_get_skb\([^;]*\);)\n"
    r"(?P<pull>[ \t]*skb_pull\(p, 202\);)"
)

def repl(m):
    ind = m.group("indent")
    return (
        f"{ind}{m.group('get')}\n"
        f"{ind}if (p == 0) {{\n"
        f"{ind}    break;\n"
        f"{ind}}}\n"
        f"{m.group('pull')}"
    )

new, n = pattern.subn(repl, src)
if n == 0:
    sys.stderr.write("inject NULL-check patch: no pkt_buf_get_skb/skb_pull "
                     "pattern matched; firmware layout may have changed\n")
    sys.exit(1)

with open(path, "w") as f:
    f.write(new)
print(f"inject NULL-check patch: added {n} guard(s) to {path}")
PY
