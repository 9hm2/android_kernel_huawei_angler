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

## Workaround until the firmware fix lands

PMKID is also affected (it lives in the M1 key-data, past the cut), so the
internal chip cannot currently feed hashcat a usable handshake **or** PMKID.
Use the external rtl88xxau for handshake/PMKID capture, or capture from a
device whose driver does not truncate EAPOL, until the cap above is patched.
