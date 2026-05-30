#!/usr/bin/env bash
# Bound the radiotap length the nexmon BCM4358 injection path trusts.
#
# inject_frame() in patches/bcm4358/<fwver>/nexmon/src/injection.c reads the
# radiotap length straight out of the injected frame:
#
#     rtap_len = *((char *)(p->data + 2));
#     ...
#     skb_pull(p, rtap_len);
#
# rtap_len is fully attacker/tool-controlled and never bounded against the
# actual skb length. A malformed frame with a large rtap_len makes the
# radiotap iterator read past p->data and the later skb_pull(p, rtap_len)
# pull beyond the buffer - both can fault the firmware. Newer nexmon chips
# (bcm4375b1) dropped this iterator path entirely for this reason.
#
# This back-ports a minimal bound: clamp/validate rtap_len against p->len and
# bail out (freeing the skb) if it does not fit, before the iterator runs.
# Idempotent.
#
# Usage: bcm4358-injection-len-check.sh <path-to-injection.c>
set -euo pipefail

SRC="${1:?usage: $0 <injection.c>}"

if [ ! -f "$SRC" ]; then
	echo "::warning::injection len-check: $SRC not found, skipping"
	exit 0
fi

if grep -q "rtap_len bounds check" "$SRC"; then
	echo "injection len-check already present in $SRC, nothing to do"
	exit 0
fi

python3 - "$SRC" <<'PY'
import re, sys

path = sys.argv[1]
with open(path) as f:
    src = f.read()

# Anchor on the line that reads the radiotap length from the frame, and add a
# bounds check immediately after it. p->len must be at least 4 (the 2-byte
# version/pad + 2-byte it_len that make up a minimal radiotap header) and at
# least rtap_len, otherwise the frame is malformed and we drop it.
anchor = "    rtap_len = *((char *)(p->data + 2));\n"
if anchor not in src:
    sys.stderr.write("injection len-check: anchor line not found; "
                     "firmware source layout may have changed\n")
    sys.exit(1)

guard = (
    anchor +
    "\n"
    "    // rtap_len bounds check: rtap_len is taken verbatim from the\n"
    "    // injected frame and is otherwise trusted by the iterator and the\n"
    "    // later skb_pull(p, rtap_len). Reject frames whose claimed radiotap\n"
    "    // length does not fit the buffer so we never read/pull past it.\n"
    "    if (rtap_len < 4 || rtap_len > p->len) {\n"
    "        pkt_buf_free_skb(wlc->osh, p, 0);\n"
    "        printf(\"rtap_len out of range\\n\");\n"
    "        return 0;\n"
    "    }\n"
)

src = src.replace(anchor, guard, 1)

with open(path, "w") as f:
    f.write(src)
print(f"injection len-check: added rtap_len bounds check to {path}")
PY
