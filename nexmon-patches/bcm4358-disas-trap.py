#!/usr/bin/env python3
# bcm4358-disas-trap.py — disassemble BCM4358 RAM firmware around the
# addresses recovered from a dongle control-flow trap.
#
# Context (besside-ng / reaver WPS-association trap):
#   The trap header comes back with poison registers (epc/lr = 0x0e0e0e0e
#   fill), so it cannot point at the faulting routine. The driver's stack
#   scan (dhd_pcie.c) instead recovers the saved LRs from the dongle stack;
#   those are the real call chain. This script turns those raw RAM addresses
#   into annotated Thumb-2 disassembly so the corrupting routine can be
#   identified and a targeted nexmon hook written for it.
#
# The downloaded RAM firmware starts at RAMSTART (0x180000 on the BCM4358),
# so a RAM address A maps to file offset A - 0x180000. ROM addresses
# (< 0x180000) are not in this blob and are skipped.
#
# Usage:
#   bcm4358-disas-trap.py <fw_bcmdhd.bin> [addr ...]
#
# With no addresses, it uses the call chain recovered from the reaver trap
# (see DEFAULT_ADDRS). Output goes to stdout (the CI prints it into the
# firmware build log).

import sys

RAMSTART = 0x180000
WINDOW_BEFORE = 24   # bytes of context to show before each address
WINDOW_AFTER  = 24   # bytes after

# Call chain recovered from the reaver/WPS trap stack scan (RAM addresses
# only; ROM and obvious data false-positives dropped). Stable, repeating
# frames first.
DEFAULT_ADDRS = [
    0x1b5ef4, 0x1b6196, 0x1b6f7e,   # repeating inner frames
    0x1c26bc, 0x1cf936,
    0x1e28d2, 0x1e190e,
]

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    from capstone.arm import ARM_GRP_JUMP
except ImportError:
    sys.exit("::error::capstone not installed (pip3 install capstone)")


def load(path):
    with open(path, "rb") as f:
        return f.read()


def interesting(insn):
    """Flag stack/context ops that matter for a corruption hunt."""
    m = insn.mnemonic
    if m.startswith(("push", "pop", "stm", "ldm")):
        return "  <-- stack/context"
    if m == "sub" and insn.op_str.startswith("sp"):
        return "  <-- stack alloc"
    if m == "add" and insn.op_str.startswith("sp"):
        return "  <-- stack free"
    if m in ("bl", "blx"):
        return "  <-- call"
    return ""


def disas_at(md, blob, addr):
    off = addr - RAMSTART
    if off < 0 or off >= len(blob):
        print("  0x%06x: <not in RAM blob (ROM or out of range)>" % addr)
        return
    start = max(0, off - WINDOW_BEFORE)
    # align start to even (Thumb)
    start &= ~1
    end = min(len(blob), off + WINDOW_AFTER)
    code = blob[start:end]
    base = RAMSTART + start
    print("  --- around 0x%06x (file off 0x%x) ---" % (addr, off))
    for insn in md.disasm(code, base):
        mark = ">>" if insn.address == (addr & ~1) else "  "
        print("  %s 0x%06x  %-10s %-24s%s" % (
            mark, insn.address, insn.mnemonic, insn.op_str,
            interesting(insn)))


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: %s <fw_bcmdhd.bin> [addr ...]" % sys.argv[0])
    blob = load(sys.argv[1])
    addrs = [int(a, 0) for a in sys.argv[2:]] or DEFAULT_ADDRS

    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    print("=== BCM4358 trap call-chain disassembly ===")
    print("blob: %s (%d bytes), RAMSTART 0x%x" %
          (sys.argv[1], len(blob), RAMSTART))
    for a in addrs:
        print()
        disas_at(md, blob, a)


if __name__ == "__main__":
    main()
