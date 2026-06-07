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
