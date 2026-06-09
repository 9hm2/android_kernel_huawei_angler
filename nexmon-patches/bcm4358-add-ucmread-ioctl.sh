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
"        case 0x604: // 1540: read d11 memory via objmem select (same proven path as\n"
"        case 0x605: // cmd 0x600). sel: 0x604=0x10000 0x605=0x20000 0x607=0x30000\n"
"        case 0x607: //      0x608=0x40000 0x609=0x50000 0x60A=0x60000 -- to find the\n"
"        case 0x608: //      d11 receive-FIFO object that holds the full plaintext body.\n"
"        case 0x609:\n"
"        case 0x60A:\n"
"        {\n"
"            // arg in:  u32 byte_offset, u32 length; arg out: arg[i]=mem[off+i]\n"
"            if (len >= 8) {\n"
"                unsigned int off, n, i;\n"
"                int sel = (cmd == 0x604) ? 0x10000 : (cmd == 0x605) ? 0x20000 :\n"
"                          (cmd == 0x607) ? 0x30000 : (cmd == 0x608) ? 0x40000 :\n"
"                          (cmd == 0x609) ? 0x50000 : 0x60000;\n"
"                struct wlc_hw_info *wlc_hw = wlc->hw;\n"
"                memcpy(&off, arg + 0, 4);\n"
"                memcpy(&n,   arg + 4, 4);\n"
"                if (n > 256) n = 256;\n"
"                if (n > (unsigned int) len) n = (unsigned int) len;\n"
"                for (i = 0; i < n; i++)\n"
"                    arg[i] = (char) wlc_bmac_read_objmem_byte(wlc_hw, off + i, sel);\n"
"                ret = IOCTL_SUCCESS;\n"
"            }\n"
"        }\n"
"        break;\n\n"
"        case 0x601: // 1537: read EAPOL RX diag bucket A (g_eapol_diag)\n"
"        {\n"
"            extern unsigned char *nexmon_eapol_diag_ptr(void);\n"
"            unsigned char *diag = nexmon_eapol_diag_ptr();\n"
"            int i; int n = len; if (n > 256) n = 256;\n"
"            for (i = 0; i < n; i++) arg[i] = (char) diag[i];\n"
"            ret = IOCTL_SUCCESS;\n"
"        }\n"
"        break;\n\n"
"        case 0x602: // 1538: read full-DATA RX diag bucket B (g_eapol_diag2)\n"
"        {\n"
"            extern unsigned char *nexmon_eapol_diag2_ptr(void);\n"
"            unsigned char *diag = nexmon_eapol_diag2_ptr();\n"
"            int i; int n = len; if (n > 256) n = 256;\n"
"            for (i = 0; i < n; i++) arg[i] = (char) diag[i];\n"
"            ret = IOCTL_SUCCESS;\n"
"        }\n"
"        break;\n\n"
"        case 0x610: // 1552: FORCE-DECRYPT -- program AMT slot 0 + WEP key for the\n"
"        {           //        foreign AP whose A2 is in arg[0..5], so its EAPOL is\n"
"            //        routed through WEP-decrypt (recover body via host RC4 XOR-back)\n"
"            extern void nexmon_forcedecrypt_program(struct wlc_hw_info *hw, const unsigned char *mac);\n"
"            if (len >= 6) {\n"
"                unsigned char mac[6]; int i;\n"
"                for (i = 0; i < 6; i++) mac[i] = (unsigned char) arg[i];\n"
"                nexmon_forcedecrypt_program(wlc->hw, mac);\n"
"                ret = IOCTL_SUCCESS;\n"
"            }\n"
"        }\n"
"        break;\n\n"
"        case 0x606: // 1542: read the d11 RX-buffer SRAM dump (1024B) captured at\n"
"        {           //        the EAPOL moment; arg[0..3]=offset into the 1024B buf\n"
"            extern unsigned char *nexmon_eapol_shm_ptr(void);\n"
"            unsigned char *diag = nexmon_eapol_shm_ptr();\n"
"            unsigned int o = 0; int i, n = len; if (n > 256) n = 256;\n"
"            if (len >= 4) memcpy(&o, arg + 0, 4);\n"
"            if (o > 1024) o = 1024;\n"
"            if (o + (unsigned int) n > 1024) n = (int) (1024 - o);\n"
"            for (i = 0; i < n; i++) arg[i] = (char) diag[o + i];\n"
"            ret = IOCTL_SUCCESS;\n"
"        }\n"
"        break;\n\n"
"        case 0x603: // 1539: read N consecutive live d11 SHM words via ROM wlc_read_shm\n"
"        {\n"
"            // arg in:  u32 byte_offset, u32 nwords (little-endian, packed)\n"
"            // arg out: arg[2*i..2*i+1] = SHM word at (byte_offset + 2*i), LE16\n"
"            // ucode SHM word [0xNNN] lives at byte offset 0xNNN*2.\n"
"            // Call ROM wlc_read_shm(wlc, off) directly @0x3085C (Thumb|1): the\n"
"            // nexmon wrapper's AT(FW_VER_ALL) does not match 7_112_300_14, so the\n"
"            // wrapper symbol has no placement -- a direct absolute call avoids it.\n"
"            unsigned short (*rom_read_shm)(void *, unsigned int) =\n"
"                (unsigned short (*)(void *, unsigned int)) (0x3085C | 1);\n"
"            if (len >= 8) {\n"
"                unsigned int boff, nw, i;\n"
"                memcpy(&boff, arg + 0, 4);\n"
"                memcpy(&nw,   arg + 4, 4);\n"
"                if (nw > 128) nw = 128;\n"
"                if (2 * nw > (unsigned int) len) nw = ((unsigned int) len) / 2;\n"
"                for (i = 0; i < nw; i++) {\n"
"                    unsigned short v = rom_read_shm(wlc, boff + 2 * i);\n"
"                    arg[2 * i]     = (char) (v & 0xff);\n"
"                    arg[2 * i + 1] = (char) (v >> 8);\n"
"                }\n"
"                ret = IOCTL_SUCCESS;\n"
"            }\n"
"        }\n"
"        break;\n\n"
)
s = s.replace(case_anchor, case_code + case_anchor, 1)
open(p, "w").write(s)
print("ucmread-ioctl: injected cmd 0x600 UCM read-back into", p)
PY
