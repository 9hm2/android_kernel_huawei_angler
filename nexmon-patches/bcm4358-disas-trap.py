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

# Call chain recovered from the reaver/WPS trap stack scan, confirmed as real
# return addresses by disassembly (each sits right after a bl). The WPS
# association IE/TLV parse path:
#   0x1b5ef4  allocator return (builds a struct: str [r4,#0xc/#0x10/#0x14])
#   0x1b6196  IE/TLV search loop (ldrb [r1,#1]=len, cmp r4, walk by length)
#   0x1b6f7e  IE parse with a large stack frame ([sp,#0x30..0x4c])
#   0x1c26bc  logger caller (msgID 0x19e); epilogue pop {r4-r8,pc}
#   0x1cf936  420-byte stack frame (add sp,#0x1a4); pop {r4-r8,sb,sl,fp,pc}
# 0x1e28d2 and 0x1e190e were data regions (stack-scan false positives) and
# are intentionally dropped.
DEFAULT_ADDRS = [
    0x1b5ef4, 0x1b6196, 0x1b6f7e,   # repeating inner frames
    0x1c26bc, 0x1cf936,
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


def disas_at(md, blob, addr, collect_calls=None):
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
        # Record bl/blx targets that land in the RAM blob so we can
        # disassemble the called function bodies (where an unbounded IE/TLV
        # parse would actually write).
        if collect_calls is not None and insn.mnemonic in ("bl", "blx"):
            ops = insn.op_str.replace("#", "")
            try:
                tgt = int(ops, 0)
                if RAMSTART <= tgt < RAMSTART + len(blob):
                    collect_calls.add(tgt)
            except ValueError:
                pass


def disas_func(md, blob, addr, nbytes=160):
    """Disassemble a called function's prologue/body from its entry."""
    off = addr - RAMSTART
    if off < 0 or off >= len(blob):
        print("  0x%06x: <not in RAM blob>" % addr)
        return
    end = min(len(blob), off + nbytes)
    print("  === called function 0x%06x (file off 0x%x) ===" % (addr, off))
    for insn in md.disasm(blob[off:end], addr):
        print("     0x%06x  %-10s %-24s%s" % (
            insn.address, insn.mnemonic, insn.op_str, interesting(insn)))


def scan_poison(blob):
    """Find where the incrementing-word poison (0x00,0x01010101,0x02020202,
    ...) literally appears in the blob, and any code building 0x01010101 /
    0x0e0e0e0e style constants -- a candidate for the routine that fills the
    corrupted context.
    """
    print("=== poison-pattern data scan (k*0x01010101 runs) ===")
    hits = 0
    i = 0
    n = len(blob)
    while i + 8 <= n and hits < 20:
        w0 = int.from_bytes(blob[i:i+4], "little")
        w1 = int.from_bytes(blob[i+4:i+8], "little")
        # a 4x-replicated byte word followed by the next-higher one
        b0 = w0 & 0xff
        if w0 == b0 * 0x01010101 and w1 == ((b0 + 1) & 0xff) * 0x01010101 \
           and b0 != 0 and b0 != 0xff:
            print("  data: file off 0x%x (RAM 0x%06x): %08x %08x ..." % (
                i, RAMSTART + i, w0, w1))
            hits += 1
            i += 8
            continue
        i += 4
    if not hits:
        print("  (no incrementing-word poison table found as data)")



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

    calls = set()
    for a in addrs:
        print()
        disas_at(md, blob, a, collect_calls=calls)

    # Disassemble the bodies of the functions actually called along the
    # chain -- this is where an unbounded IE/TLV parse would write past its
    # buffer and corrupt a neighbouring saved context.
    if calls:
        print()
        print("=== called function bodies (bl/blx targets in RAM) ===")
        for t in sorted(calls):
            print()
            disas_func(md, blob, t)

    print()
    scan_poison(blob)


if __name__ == "__main__":
    main()
