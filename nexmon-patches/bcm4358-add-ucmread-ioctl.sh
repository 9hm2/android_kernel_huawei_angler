#!/usr/bin/env bash
# Inject a NON-DESTRUCTIVE "read live d11 UCM (microcode memory)" ioctl into the
# nexmon bcm4358 ioctl.c, so we can verify on-device whether a byte-patched
# ucode.bin actually reaches the running d11 core.
#
# The nexmon ucode deployment decompresses ucode_compressed.c into the d11 UCM
# via wlc_bmac_write_objmem_byte(wlc_hw, idx, value, OBJADDR_UCM_SEL=0), idx ==
# linear ucode.bin offset (no swizzle). The inverse reader wlc_bmac_read_objmem_byte
# lets us read UCM[idx] == (what is actually executing). cmd 0x600 (1536) is
# unused (nexmon uses 400-428 + 700-703; WLC stock <=263). READ ONLY -> safe.
#
# Usage: bcm4358-add-ucmread-ioctl.sh <path-to-ioctl.c>
set -euo pipefail
SRC="${1:?usage: $0 <ioctl.c>}"
[ -f "$SRC" ] || { echo "::warning::ucmread-ioctl: $SRC not found, skipping"; exit 0; }
if grep -q "UCM read-back" "$SRC"; then
    echo "ucmread-ioctl: already present in $SRC"; exit 0
fi

python3 - "$SRC" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()

inc_anchor = "#include <channels.h>\n"
if inc_anchor not in s:
    sys.stderr.write("ucmread-ioctl: include anchor not found\n"); sys.exit(1)
s = s.replace(inc_anchor,
    inc_anchor + "#include <objmem.h>            // UCM read-back (wlc_bmac_read_objmem_byte)\n", 1)

case_anchor = "        default:\n            ret = wlc_ioctl(wlc, cmd, arg, len, wlc_if);"
if case_anchor not in s:
    sys.stderr.write("ucmread-ioctl: default-case anchor not found\n"); sys.exit(1)
case_code = (
"        case 0x600: // 1536: UCM read-back -- read live d11 microcode memory\n"
"        {\n"
"            // arg in:  u32 offset, u32 length (little-endian, packed)\n"
"            // arg out: arg[i] = UCM byte (offset+i); UCM[x] == ucode.bin[x]\n"
"            if (len >= 8) {\n"
"                unsigned int off, n, i;\n"
"                struct wlc_hw_info *wlc_hw = wlc->hw;\n"
"                memcpy(&off, arg + 0, 4);\n"
"                memcpy(&n,   arg + 4, 4);\n"
"                if (n > 256) n = 256;\n"
"                if (n > (unsigned int) len) n = (unsigned int) len;\n"
"                for (i = 0; i < n; i++)\n"
"                    arg[i] = (char) wlc_bmac_read_objmem_byte(wlc_hw, off + i, 0);\n"
"                ret = IOCTL_SUCCESS;\n"
"            }\n"
"        }\n"
"        break;\n\n"
)
s = s.replace(case_anchor, case_code + case_anchor, 1)
open(p, "w").write(s)
print("ucmread-ioctl: injected cmd 0x600 UCM read-back into", p)
PY
