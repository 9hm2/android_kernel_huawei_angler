# BCM4358 monitor-mode EAPOL truncation — reverse-engineering notes

## Symptom

On the on-board BCM4358, capturing a WPA2 4-way handshake in monitor mode
"works" (wifite/airodump see the client and the EAPOL frames), but the
captured EAPOL-Key frames are **malformed and uncrackable** — aircrack/hashcat
never recover the PSK even though the handshake appears complete.

## Measurement (two on-device tcpdump captures, analysed offline)

A custom pcap parser (radiotap + 802.11 + SNAP/EAPOL, with CRC32 FCS check)
was run on two captures (`eapol.pcap`, 3022 pkts; `eapol2.pcap`, 40670 pkts).
Findings, all from real frames:

- The monitor path itself is **healthy**: large data frames arrive intact up
  to 1904 bytes, radiotap is present, and the FCS flag is truthful
  (CRC32 of a sampled 564-byte frame matched its trailing FCS exactly).
- **Every** real EAPOL-Key frame (SNAP `aa aa 03 00 00 00` + ethertype
  `0x888e`) is truncated to a **fixed 90 bytes on-air**, regardless of its
  declared length:

  | msg | declared EAPOL len | bytes actually present | missing |
  |-----|--------------------|------------------------|---------|
  | M1  | 95                 | 52                     | 43      |
  | M2  | 119                | 52                     | 67  (the MIC) |
  | M3  | 151                | 52                     | 99  (the GTK) |
  | M4  | 95                 | 52                     | 43      |

  All four messages of the handshake are present (M1×9, M2×8, M3×8, M4×8
  across both files) but each is cut at the same point.

- The cut is **not** a capture/snaplen artifact: `caplen == origlen` for every
  packet, i.e. the frame already reached the host truncated.
- The cut is **EAPOL-specific**: encrypted data frames vary freely (80–112+
  bytes); only the unencrypted EAPOL frames are pinned to 90.

### Why this kills cracking

The WPA2 key MIC (what hashcat verifies the passphrase against) sits at
roughly byte 81 of the EAPOL-Key body, but the frame is cut at body byte ~52.
So the MIC (M2) and the encrypted GTK (M3) are never captured. The handshake
is irrecoverably incomplete on the wire.

## Root cause (architecture)

The BCM4358 is fullmac. While associated/observing, the firmware **intercepts
802.1X/EAPOL** specially (normally to hand it to the host supplicant) and
copies it into a small fixed event/control buffer. The monitor path then
clones **that already-truncated copy**, so 90 bytes is all that ever reaches
the radiotap interface. Plain data frames are not intercepted this way, which
is why only EAPOL is short.

### Confirmed independently (tshark + byte accounting)

- Wireshark's own dissector flags every one as `Malformed Packet: EAPOL`
  with `eapol.len` = 95 / 119 / 151 but the frame body cut short. The
  handshake sequences cleanly M1(95) -> M2(119) -> M3(151) -> M4(95), all
  truncated at the identical point.
- Byte accounting of a cut M1: on-air 802.11 = 90 bytes = 26 (hdr+QoS) + 8
  (SNAP+ethertype) + 56 (EAPOL header+partial body); the **tail is zero-pad**
  (`00 00 00 ...`), and the trailing 4 bytes are NOT a valid FCS. So the
  firmware does not "cut" the wire frame -- it copies the EAPOL into a
  **fixed 96-byte (0x60) buffer and zero-fills the remainder**:
  96 = 90 on-air + 6 stripped by nexmon's `wl_monitor_radiotap`.
- The frame reaches the host as a `WLC_E_EAPOL_MSG` (event type 25) -- the
  firmware "Event encapsulating an EAPOL message" path -- whose payload area
  is the 0x60 buffer. That is the cap.
- Only EAPOL is affected because only EAPOL takes this event path; every
  other unencrypted frame on the test net was a 54-byte QoS-null (no
  payload) or CCMP-encrypted, so there is no non-EAPOL unencrypted payload
  frame to compare, but the mechanism (event-encapsulation) is EAPOL-specific
  by design.

### Why the patch site is hard to pin statically

The cap is NOT a literal: an exhaustive scan found no `#0x60` (96), `#0x5a`
(90), or `#0x19` (WLC_E_EAPOL_MSG=25) immediate anywhere in the blob. The
size and the event type both come from struct fields / computed values, so
the truncation is structural (an event-buffer template size), reached on the
fullmac 802.1X RX path (RX handler `0x1a560c` -> EAPOL classifiers
`0x19a182` / `0x19ace8` / `0x19a4d8`). Pinning the exact store that sets the
0x60 payload length needs dynamic confirmation (a driver-side probe of the
firmware-delivered skb->len on the EAPOL monitor path) rather than more
static constant scanning.

### Driver side is clean

`dhd_rx_mon_pkt` (dhd_linux.c) hands the firmware's skb straight to the
monitor netdev and only prepends a radiotap header; the EAPOL check at
dhd_linux.c:3048 runs AFTER the monitor diversion and does not shorten the
frame. So nothing in the kernel truncates EAPOL -- it arrives from the
firmware already capped at 96 bytes. The fix must be in the firmware.

This is the same class of bug as the three dongle traps already fixed
(alloc 0x216dfc, free 0x182352, WPS asserts 0x18554a/0x183bf0): a concrete,
RAM-resident firmware defect — here a fixed-size copy on the EAPOL path.

## Located so far (in the downloaded RAM blob, RAMSTART 0x180000)

The EAPOL classifier/parser that recognises SNAP + ethertype `0x888e`:

- `0x19a4d8` — SNAP+EAPOL classifier/key-info decoder. Checks
  `aa aa 03 00 00 00`, loads the `0xffff888e` mask/ethertype at `0x19a52c`
  (`cmp` at `0x19a530`), then decodes the EAPOL-Key `key_info` bits
  (M1/M2/M3/M4) via `ubfx`. Contains length gates `cmp r7,#0x6a` (106) at
  `0x19a4ea` and `cmp r2,#0x5e` (94, the declared EAPOL length) at `0x19a576`.
- `0x19ace8` — second EAPOL classifier (TX/host side), loads `0xffff888e`
  at `0x19ad02`; called from the RX handler `0x1a560c` at `0x1a59a8`.
- The three `0xffff888e` constants live at data `0x19a5fc`, `0x19ad50`,
  `0x1a3b54`.

The actual fixed ~96-byte copy/alloc (96 = 90 on-air + 6 stripped by nexmon's
`wl_monitor_radiotap`, which itself copies `p->len-6` and does NOT impose the
90 limit) is in a deeper DMA/event helper not yet pinpointed — a
fixed-immediate memcpy-length scan (0x5a/0x5e/0x60/0x66/0x6a in r2 before a
bl) found no match, so the length is computed/structural, not a literal.

## Next step to finish the fix

Trace the buffer that the EAPOL interceptor copies into: from `0x1a560c`'s
RX path, follow where the 802.1X frame is duplicated for host delivery and
find the size field/allocation that caps it near 96. Patch that cap to carry
the full frame length (bounded by the real RX length) so the monitor clone
receives the complete EAPOL-Key frame. Then a handshake captured on the
internal chip becomes complete and crackable — the ACK-independent,
fullmac-correct path to WPA2 on the on-board radio.

## On-device confirmation (DHD-MON-EAPOL + DHD-MON-CENSUS probes)

A diagnostic in `dhd_rx_mon_pkt` (dhd_linux.c) printed, per monitor frame,
the firmware-delivered `skb->len`:

- **EAPOL probe:** every EAPOL is `skb->len=114` (= 24 radiotap + 90 on-air),
  `avail_after_hdr=52`, regardless of `declared_len` 95/119/151. The driver
  receives it already truncated -> the cut is 100% in firmware.
- **Census probe:** other frames on the same monitor path arrive FULL —
  beacons 245/281, encrypted QoS-data (fc0=0x88, fc1=0x42) 1353/1358 and up
  to **1904** bytes. Only the cleartext EAPOL is pinned to 114.

So the truncation is **EAPOL-specific**, not a global per-frame or
first-RX-fragment cap, and the nexmon `wl_monitor` hook itself is fine (it
delivers 1904-byte frames intact). The fix is therefore feasible and should
be **gated on monitor mode** (`wl->wlc->monitor & 0xFF`) so the phone's own
WPA client — which legitimately needs the firmware to intercept its EAPOL —
is unaffected.

### The captured stub is zero-filled (data is gone)

The tail of a cut EAPOL frame is `00 00 00 ...`, not EAPOL continuation, and
the trailing 4 bytes are not a valid FCS. So the monitor receives a SEPARATE
fixed ~96-byte zero-filled buffer, not the original packet with a short len.
Consequently the fix cannot just restore `p->len` in `wl_monitor` — the bytes
are not there. The firmware must be made to deliver EAPOL to the monitor via
the same full path as encrypted data (i.e. skip the EAPOL-specific short
staging) when monitor mode is active.

### Branch located

In the RX handler `0x1a560c`, the SNAP/LLC handling splits at:

    0x1a58a0  bl 0x19a182        ; ethertype-intercept classifier
    0x1a58a4  cbz r0, 0x1a58c2   ; r0!=0 (intercept) -> SHORT path 0x1a58c2
    0x1a58c2  ldrh r1,[sp,#0xc2]; subs r1,#6   ; 6-byte (EAPOL/AARP/IPX) strip
    0x1a58d8  ...               ; FULL/normal path (14-byte LLC strip)

`0x19a182` returns nonzero for the intercepted ethertypes. This is the host
802.3 conversion split, not yet proven to be the exact instruction that sizes
the 96-byte monitor stub (no `#0x60`/`#0x5a`/`#0x38` immediate exists; the
size is structural). Pinpointing the store that sets the 96-byte stub length
needs one more on-device probe (log the rx pkt pointer/len at the EAPOL
staging vs. the value handed to `wl_monitor`), then a monitor-gated HookPatch
there.

## Workaround until the firmware fix lands

PMKID is also affected (it lives in the M1 key-data, past the cut), so the
internal chip cannot currently feed hashcat a usable handshake **or** PMKID.
Use the external rtl88xxau for handshake/PMKID capture until the cap is
patched.

## SOLVED — the correct fix (v2)

The first hook (0x19ad06, on the host 802.3-conversion path 0x19ace8) did
nothing: on-device the build marker confirmed the fix kernel was flashed
(uname -r 3.10.73-<stamp>, DHD-MON-BUILD printed) yet EAPOL stayed at
skb->len=114. Reason: in monitor mode the firmware does NOT run the host
path — at 0x1a31b4 / 0x1a320e it reads wlc->monitor (`ldr r3,[r5,#0x208]`)
and, if set, branches to the monitor delivery at 0x1a32ea, bypassing the
host EAPOL forwarder entirely. So the hooked site never executed.

The real EAPOL special-case is INSIDE the monitor branch:

    0x1a3354  ldr  r1,[sp,#0x10]    ; frame ethertype
    0x1a3356  movw r3,#0x888e       ; EAPOL
    0x1a335a  cmp  r1,r3
    0x1a335c  beq  0x1a3366         ; EAPOL -> special handler (ROM 0x23d68)
    0x1a335e  movw r3,#0x88b4
    0x1a3362  cmp  r1,r3
    0x1a3364  bne  0x1a3376         ; neither -> normal FULL monitor delivery
    0x1a3366  ...  bl 0x23d68       ; emits the fixed ~96B EAPOL stub

0x23d68 is ROM (not patchable) but does not need to be: rewriting the 4-byte
`movw r3,#0x888e` at 0x1a3356 to `movw r3,#0` makes EAPOL never match, so it
falls through to the full-length monitor delivery at 0x1a3376 (the same path
encrypted data uses, proven to carry up to 1904 bytes). This branch only runs
in monitor mode, so the phone's WPA client is unaffected and no separate gate
is needed. The 0x88b4 special case is left intact. Implemented as a verified,
idempotent 4-byte binary patch (bcm4358-eapol-monitor-fullframe.sh) applied
to the linked firmware after make.

## STATUS: v2 fix (0x1a3356) ALSO ineffective — disabled

On-device (uname 3.10.73-...-89ede527, DHD-MON-BUILD v2 confirmed flashed),
EAPOL stayed at skb->len=114. So 0x1a3356 is NOT the truncation site either —
its surrounding code (0x1a32ea region) is RX statistics counters
([+0x40]/[+0x44] increments) and a 0x23d68 stat/notify call, not the frame
copy. The 0x1a3356 binary patch is kept in-tree for the record but is NO
LONGER applied by the CI.

### Candidate sites tried and DISPROVEN (all static guesses, all wrong)

1. 0x19ad06 — host 802.3 EAPOL forwarder (0x19ace8). Not run in monitor mode
   (the firmware branches to the monitor path at 0x1a31b4/0x1a320e on
   wlc->monitor before reaching it).
2. 0x1a3356 — `movw r3,#0x888e` inside the monitor branch, but on the RX
   statistics path (0x23d68 is a stat/notify, ROM), not the copy.
3. 0x19bb0a — `movw r1,#0x888e` after an MTU (0x5dc) check; sets a 0x10 flag
   in [r4,#0x18]. Plausible classifier, but the function (entry 0x19b9de)
   does NOT read wlc->monitor and no bit-0x10 consumer that truncates was
   found, so it is unproven.

### Why static analysis stalled

The monitor RX→clone path is struct/table-driven: the 90→96 size is never a
literal (#0x60/#0x5a absent), wlc->monitor (offset 0x208) is read at
0x19a244/0x1a31b4/0x1a320e/0x1a3d26/0x1a649e/0x1a6d04 but the actual EAPOL
clone shortening is reached indirectly. Three guessed patch sites were each
disproven by the on-device DHD-MON-EAPOL probe (skb->len stayed 114).

### Correct next approach (dynamic, not more guessing)

Find the call that hands the monitor tap its packet for EAPOL and read the
length THERE, rather than guessing the constant. Concretely: add a driver
probe that, for an EAPOL monitor skb, also dumps a few words of firmware
shared memory / the rx descriptor around the source buffer, or bisect by
patching each wlc->monitor consumer (0x1a31b4 vs 0x1a320e vs 0x1a3d26 …) one
at a time behind the build marker, observing which one changes skb->len.
Only patch once a single change is shown to move skb->len off 114.

## RESOLVED (diagnosis complete): the cut is in ROM, before nexmon sees it

The chain hypothesis was tested directly and DISPROVEN. The firmware patch
smuggled p->len and p->next out via the radiotap TSF; on-device:

    NEXMON-EAPOL-CHAIN: fw p->len=96 p->next=0 ... skb->len=114

p->next=0 for every EAPOL frame -> the packet is NOT chained. The 96-byte
packet handed to nexmon's wl_monitor_radiotap genuinely contains only ~90
on-air bytes; the rest of the EAPOL is already gone.

Per nexmon's own monitormode.c, wl_monitor (= wlc_monitor) lives in ROM, and
the hook only sees the packet wlc_monitor already built (it hooks
pkt_buf_get_skb and checks lr==0x1863f to detect the wlc_monitor caller). The
monitor branch in RAM (0x1a32ea) calls ROM handlers 0x23d68 (EAPOL special
case) and 0x2e958 with the frame; both are < 0x180000 (ROM). So the EAPOL is
truncated to ~90 bytes inside ROM, BEFORE any RAM/nexmon code runs.

### Conclusion

Delivering full-length EAPOL to the monitor interface is NOT achievable by
firmware patching on this chip/firmware:
- the truncation is in ROM (wlc_monitor / its EAPOL special handler), and
- nexmon itself notes "there are no free ROM patches left" on this build
  (no flashpatch config slot to redirect a ROM instruction).

This is the same class of limit as monitor-mode TX-ACK: a ROM-resident
behaviour with no free flashpatch slot. Unlike the three dongle traps (RAM,
hookable) this one cannot be fixed in the downloaded blob.

### Practical upshot

The on-board BCM4358 captures EAPOL only as a 90-byte stub (M2 MIC and M3 GTK
lost), so it cannot feed aircrack/hashcat a crackable handshake or PMKID. For
WPA2 handshake/PMKID capture use the external rtl88xxau. Everything else on
the internal chip (monitor, injection, channel control, deauth, MAC spoof,
the three trap fixes, WPS stability) works.

The diagnostic probes (DHD-MON-EAPOL/CENSUS/CHAIN and the nexmon TSF marker)
were the means to prove this and are removed from the shipping build.

## RE tooling upgrade + memory map (radare2)

Installed radare2 5.5.0 (+ r2pipe, JRE) and re-analysed the RAM blob with
proper function/xref analysis (run r2 with -N to disable sandbox). r2 resolves
the real branch targets the raw capstone disasm got wrong: calls that looked
like "0x23d68" are actually ROM (r2 shows 0xffea3d68; ROM base wraps).

Confirmed memory map (from nexmon definitions.mk / rom_extraction):
  ROM   0x000000 .. 0x0A0000   (640 KiB)   <- NOT in fw_bcmdhd.bin
  RAM   0x180000 .. 0x240000   (downloaded blob, what we have)
  UCODE 0x20c9c0 ; templateram 0x219ed8

The monitor RX function fcn 0x1a3068 (910 bytes) was mapped cleanly. Its
calls split as:
  RAM (patchable): 0x182f38, 0x18b380, 0x18ce80, 0x18cebc  -- all stats /
                   counter wrappers, NOT the packet copy
  ROM (0x0..0xA0000, not patchable, not in blob): 0x0835f8, 0x0844a4,
                   0x084b20, 0x084c34, 0x09c4f0, 0x09c518, 0x0a3d68 (the
                   EAPOL special case), 0x0ae958, 0x0b81b0, 0x0c6c7c, 0x0f2178
Plus wl_monitor itself is ROM (the nexmon hook keys on lr==0x1863f, i.e. ROM
0x1863e).

So the monitor clone (and the EAPOL 90-byte cut) is produced entirely by ROM
routines; the RAM monitor function only updates counters around the ROM call.

### To get the full picture: dump the ROM

The 0x0..0xA0000 ROM can be read from the device (no flashing) and then
disassembled with r2 to find the exact EAPOL truncation and whether any RAM
caller can supply the full frame instead. Per nexmon's rom_extraction:
    dhdutil membytes -r 0x0 0xA0000 /sdcard/rom.bin
(or a small in-driver membytes reader using dhdpcie_bus_membytes, which the
trap dumper already proved can read dongle memory). With rom.bin loaded in r2
at base 0x0 alongside the RAM blob at 0x180000, the whole monitor path becomes
analysable end to end.

## ROM dumped — full monitor/EAPOL chain mapped (radare2)

Dumped the live ROM (0x0..0xA0000, 655360 bytes, validated: 256 distinct
byte values, 6.3% zero) off the device with bcm4358-romdump.c, and analysed
ROM+RAM together in r2 (ROM at 0x0, RAM blob at 0x180000). The chain that was
invisible before is now fully resolved:

- **wl_monitor = ROM 0x18628**. Allocates a new skb sized `p->len - 6`
  (`ldrh r7,[r2,0xc]; subs r7,6; bl 0x8fd2c`) and memcpy's `p->data+6` for
  `p->len-6` bytes. So the output size is governed entirely by the incoming
  packet's `p->len` field (offset 0xC). For EAPOL that field is already 96.
  The nexmon hook keys on lr==0x1863f (the `mov r4,r0` right after the alloc).
- **wlc_monitor = ROM 0x1efc0**. Calls wl_monitor at 0x1f0a6 with the packet
  in r6. It is reached indirectly (no direct bl/b.w and no absolute function
  pointer found — a base+offset callback in the wlc RX dispatch), so the
  caller that supplies the 96-byte packet is via a computed RX callback.
- **EAPOL snoop/event path = ROM 0x23d68 -> 0x23cc8**. 0x23d68 matches
  ethertype 0xffff888e (const @0x23e0c) and 0xffff88b4, and calls 0x23cc8.
  0x23cc8 builds a `WLC_E_EAPOL_MSG` event (event id 0x19=25 at 0x23cf2,
  allocator 0x53408), copying `[r4,0x14]` bytes (0x23d3a/0x23d3c `bl 0x35f8`)
  where the length comes from its caller (the full frame, `[r7,0xc]-0xe`).
  So the host-supplicant EAPOL event carries the FULL frame; the 96-byte cut
  is specific to the MONITOR clone, not this event.

- The size 96 is NOT a literal anywhere in ROM or RAM (no 0x60/0x5a/0x36
  immediate) — it is computed and lands in the monitor packet's `p->len`
  before wl_monitor sees it.

### Where this leaves the user's "grab it earlier" idea

The full EAPOL provably exists in RAM on the host-event path (0x23cc8 copies
the full length to the supplicant). The monitor path, however, is handed a
separate packet whose `p->len` is already 96 by the time wl_monitor/wlc_monitor
run, and that packet's buffer past 90 bytes is zero (proven by the earlier
post-cut=0 probe). The remaining unknown is the computed RX callback that
supplies the 96-byte packet to wlc_monitor; pinning it is a few more static
hops (resolving the wlc RX dispatch callback table) or one dynamic caller-chain
log at wlc_monitor. Until then, rtl88xxau remains the route for crackable
WPA2 handshake/PMKID capture; everything else on the internal chip works.

## Found the RAM monitor-feed point (patchable): 0x1a6d28

Resolving the wlc_monitor (entry 0x1ecc4) callers with ROM+RAM in r2 gave
three: ROM 0x1f116, ROM 0x1f13e, and **RAM 0x1a6d28** (patchable!). The RAM
one is the live monitor feed, inside fcn 0x1a6c8a (the RX receive path):

    0x1a6c8e  ldr  r6, [r1, 8]        ; r6 = received packet
    ...
    0x1a6d04  ldr  r3, [r4, 0x208]    ; wlc->monitor
    0x1a6d08  cbz  r3, 0x1a6d2c       ; not monitor -> skip
    0x1a6d1a  mov  r0,r4; r1,r6; r2,r5
    0x1a6d28  bl   0x1ecc4            ; wlc_monitor(wlc, packet=r6, r5)

This is the exact point the user proposed: the packet r6 is fed to the
monitor chain here, in RAM, gated on wlc->monitor, BEFORE the ROM
wlc_monitor/wl_monitor build the radiotap clone. fcn 0x1a6c8a is the receive
path (r6 = [arg,8]); the EAPOL host-event copy (0x23cc8, which makes the 96B
buffer) is a separate branch. So if r6 still has the full length ([r6,0xc])
here, redirecting/cloning it full-length at 0x1a6d28 would give the monitor
the complete EAPOL.

The one remaining fact to confirm (one build): is [r6,0xc] at 0x1a6d28 the
full EAPOL length or already 96? If full, this is the fix site; if 96, the
truncation is upstream of the RX path too. This is a precise, RAM-resident,
single-measurement question — not guesswork.

## FINAL (ROM-proven): EAPOL is in a fixed ~96B pool lbuf from the start

The feed probe at 0x1a6d28 measured feed_len=96 (post-cut bytes zero) for
every EAPOL frame: the packet is ALREADY 96 bytes at the earliest patchable
RAM monitor-feed point, not just inside the ROM clone. Combined with the full
ROM map, the mechanism is now conclusive:

- The EAPOL handling uses a FIXED-SIZE pool lbuf. The event allocator chain
  0x23cc8 -> 0x53408 -> 0xdfc hands out fixed pool buffers (memset 0x40 region,
  pool at [wlc+..]). The EAPOL (WLC_E_EAPOL_MSG, id 0x19) is copied into one of
  these ~96-byte pool lbufs very early.
- Every later consumer — the host-supplicant event, the monitor-RX path
  (0x1a3068/0x1a6c8a), wlc_monitor (0x1ecc4), wl_monitor (0x18628) — sees that
  same 96-byte lbuf. The probes proved p->len=96 and feed_len=96 at each stage,
  with zero padding past 90 bytes.
- The 96 is the pool lbuf size (structural), which is why no 0x60/0x5a literal
  exists in ROM or RAM.

So the full 155+ byte EAPOL never exists in any single contiguous buffer after
reception — only in the chip's hardware RX FIFO at the instant of receipt,
which is not reachable from patchable code. Redirecting/cloning "earlier" does
not help because the earliest patchable point already holds the 96-byte lbuf.

### Conclusion on the MONITOR-CLONE path (firmware)

Fixing the *monitor radiotap clone* to carry the full EAPOL is NOT achievable by
patching: the ROM clone reads `p->len` (already 96 for EAPOL at the earliest
patchable RAM feed point), and the truncation is in ROM, not RAM. Proven end to
end with the dumped ROM in r2 plus on-device length probes — not inferred.

> CORRECTION (see "PASSIVE CAPTURE PROOF" below): the above on-device probes
> were ALL taken with an active association (reaver / wpa_supplicant), i.e. on
> the our-BSS supplicant-snoop path, which is NOT the same path a purely passive
> foreign frame takes. A clean passive capture refutes the "not achievable"
> verdict: the full foreign EAPOL **is** in dongle RAM.

## PASSIVE CAPTURE PROOF (pass01.cap) — truncation is EAPOL-specific, frame is in RAM

A 100% passive capture (no own association; foreign AP 1a:26:54:05:2f:73, foreign
client e4:c7:67:11:54:04, deauth to force a handshake) settled it:

- **Beacons: full** (253 B). **Foreign DATA frames: FULL — up to 1490 B** (280 of
  them). **EAPOL: ALL exactly 86 B**, regardless of real length (M1's `Length: 95`
  field survives but the body is cut right after the 32-byte ANonce).
- So it is NOT a global RX/DMA cap and NOT data-frame-general. Full 1490-byte data
  frames prove the RX path/DMA delivers full frames into RAM. The cut is a
  **fixed, EAPOL-specific truncation to 86 on-air bytes**.
- Therefore the **full foreign EAPOL is present in dongle RAM** and is recoverable
  in principle — the earlier "no contiguous full frame in RAM" was an artifact of
  measuring only the associated/snoop path.

Confirmed in r2: the snoop `0x23d68` matches ethertype `0xffff888e`, strips 14
bytes and calls the event builder `0x23cc8`, which copies the **full** `len-14`
into a `WLC_E_EAPOL_MSG` (id 0x19) event and sends it (`0x29fa8 -> 0x2ce10`). The
snoop is gated on `[[r0],0x9d] != 0` and `[r0,0x222] == 0` (0x23d7a / 0x23d82) —
flags, NOT a BSS-membership check.

### FIX IMPLEMENTED (nexmon source) — restore full EAPOL on the monitor clone

Avenue 2, chosen. The monitor clone is just `memcpy(p->data+6, p->len-6)` in
nexmon's `monitormode.c`; for unprotected EAPOL `p->len` was clamped to ~92 but
the full frame is still in the lbuf. `bcm4358-monitor-eapol-fulllen.sh` patches
`wl_monitor_hook()` (the dispatcher for BOTH radiotap and IEEE80211 modes) to
detect an unprotected EAPOL data frame (SNAP 0x888E) and restore `p->len` from
the 802.1X length field before the clone runs. Bounded (<=600), grow-only, so a
wrong guess cannot fault. Wired into CI next to the underflow guard. The 86-byte
frame already carries the correct 802.11 addressing, so the recovered clone is a
fully-addressed, crackable handshake — no host correlation, no event needed.
Requires a `build_nexmon=true` build. Verify: passive capture, EAPOL frames now
full length (M1 with PMKID, M2/M3 with MIC), `hcxpcapngtool` extracts a hash.

### Two avenues to deliver the full foreign EAPOL

1. **Event reinjection (already coded).** If the snoop/event fires in passive
   monitor mode, the existing `WLC_E_EAPOL_MSG` handler delivers the full body.
   Limitation: the event payload is stripped to the 802.1X body (no MACs); only
   `event->addr` (the TA/AP) is known, so a *foreign* handshake cannot be fully
   re-addressed (client MAC missing) for hcxpcapngtool. Good for our-STA frames,
   weak for foreign.
2. **Patch the monitor-clone truncation (preferred for passive).** The existing
   86-byte monitor frame already has the CORRECT 802.11 addressing; only the
   EAPOL body is cut. Restoring the body length on the monitor clone yields a
   perfectly-addressed full handshake. Open task: locate the instruction that
   sets the EAPOL monitor packet's `p->len` to ~92 (86+6) while data frames stay
   full — it is downstream of the snoop, on the monitor-feed path, and the full
   body is still in the buffer (proven by the event copy).

The next on-device probe should log, in PASSIVE mode, the EAPOL packet length at
the monitor feed (`0x1a6c8a`/`wl_monitor 0x18628`) and whether bytes past the cut
are non-zero — pinning the exact truncation instruction to patch.

## (superseded) BREAKTHROUGH — the full EAPOL is recoverable via the EVENT channel (no patch)

The "not achievable" verdict above was about the *monitor clone only*. It missed
a second, independent copy of the same frame that the ROM analysis itself had
already surfaced (this file, "host-event path"): the firmware's EAPOL snoop
(ROM 0x23d68 -> 0x23cc8) builds a **WLC_E_EAPOL_MSG event (id 25 / 0x19)** that
encapsulates the *whole* EAPOL frame — it copies the full length into a 0xdfc
(3580-byte) event buffer, NOT the 96-byte monitor lbuf. Re-reading the r2 trace:
the event carries the complete M1 (RSN PMKID) / key data; only the monitor clone
is capped at 96.

Two facts make this directly usable from the driver, with **no firmware patch**:

1. The event rides the in-band Broadcom event channel (ETHER_TYPE_BRCM), which
   `dhd_rx_mon_pkt()` explicitly passes through (it returns -1 for BRCM so the
   normal event handler runs). So the full EAPOL reaches the host *even while
   monitor_type is set*.
2. The host just has to **subscribe** to the event — the stock driver does not
   `setbit(eventmask, WLC_E_EAPOL_MSG)`, which is why the full frame was never
   seen before. Enabling bit 25 makes the firmware emit it.

### Driver implementation (this branch)

`drivers/net/wireless/bcmdhd/dhd_linux.c`:
- `dhd_preinit_ioctls()`: `setbit(eventmask, WLC_E_EAPOL_MSG)` (under
  `CONFIG_BCMDHD_MONITOR_MODE`) so the firmware delivers the full EAPOL event.
- `dhd_mon_eapol_reinject()`: from the event's payload (`*data`, length
  `ntoh32(event->datalen)`, peer in `event->addr`) it rebuilds a complete
  802.11 Data frame — minimal radiotap + FromDS 802.11 header (addr1=our STA
  `dhdp->mac`, addr2/3=AP `event->addr`) + LLC/SNAP(0x888E) + the full EAPOL body
  — and injects it into the monitor netdev via `netif_rx`.
- `dhd_wl_host_event()`: when `monitor_type` is set and the event is
  `WLC_E_EAPOL_MSG`, calls the reinject. A `DHD_ERROR` line logs the injected
  length + AP MAC so the first on-device run confirms format/length.

### Scope (honest)

The event fires for EAPOL **our STA receives**. That covers the modern
**clientless PMKID attack**: we associate to the target AP, the AP's M1 (with the
RSN PMKID) is received and re-injected full-length into the monitor capture, and
`hcxdumptool`/`hcxpcapngtool` -> hashcat `-m 22000` cracks it — entirely on the
internal BCM4358, no external dongle, no firmware patch. It does NOT recover a
**foreign** client's 4-way handshake (we are not the recipient, so no event); for
that passive case rtl88xxau remains the route. Everything else on the internal
chip already works (monitor, injection, channel control, deauth, MAC spoof, the
three trap fixes, WPS stability).

### To verify on device (one build)

1. Flash the new kernel; `dmesg | grep -i "injected full EAPOL"`.
2. Put a monitor vif up + run the PMKID capture against an AP you associate to
   (e.g. `reaver-internal.sh` holds the assoc, or a plain `wpa_supplicant` open
   assoc), capturing on the monitor vif with `hcxdumptool`/`tcpdump`.
3. Confirm the captured EAPOL is full length (M1 with PMKID, not 90 bytes) and
   that `hcxpcapngtool` extracts a `WPA*01*` PMKID line.
   The `DHD_ERROR` log prints the exact payload length/format from the firmware,
   which pins whether the event payload includes a leading ethernet header (the
   reinject auto-detects and strips it).

## CONCLUSIVE (multi-evidence): passive crackable MIC not achievable on this chip

The full-length recovery made the monitor frames the right SIZE (133/157/189,
tshark+aircrack call it a "valid handshake"), but inspecting the raw bytes shows
the **Key MIC and key-data past byte ~86 are zero/stale** — only the 802.11
header + nonces are real (M1 ANonce, M2 SNonce). hcxpcapngtool extracts nothing;
hashcat cannot crack a zero MIC. So the monitor buffer simply does NOT contain
the secret.

Every attempt to reach the full frame (where the MIC does exist — the snoop /
RX-classifier path) destabilises the dongle:
- the p->next probe dereferenced an invalid pointer -> trap + firmware reload;
- the full-length recovery inflates p->len on the shared RX packet, which the
  snoop/association path then over-reads -> dongle trap (type 0x4 @ epc 0x4c58,
  lp 0x1a3b3f) the moment we associate in monitor mode.

The snoop that copies the full frame (incl. MIC) into WLC_E_EAPOL_MSG is gated
off in monitor mode (`[wlc,0x222]` monitor flag must be 0; `[[wlc],0x9d]` must be
1) and its gate is in ROM (no free flashpatch slots). Bridging it via a RAM
trampoline is high-risk and, per the traps above, destabilises the dongle.

**Verdict:** monitor-mode passive capture of a crackable WPA2 handshake MIC /
PMKID is not safely achievable on the internal BCM4358. The chip captures the
full handshake STRUCTURE and the nonces, plus everything else (monitor,
injection, channel, deauth, MAC spoof, beacons, full data frames), but the EAPOL
MIC is not present in any monitor-reachable buffer. Use rtl88xxau for crackable
passive handshakes/PMKID. The recovery patch is disabled in CI (it gave
false-positive "valid" handshakes and could trap on association); it remains in
the tree for reference.
