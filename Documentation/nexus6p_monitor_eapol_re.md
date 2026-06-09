# BCM4358 (Nexus 6P) monitor-mode EAPOL truncation — reverse-engineering writeup

**Device:** Huawei Nexus 6P · Broadcom **BCM4358** · firmware **7_112_300_14_sta** · PCIe fullmac
**Driver:** `drivers/net/wireless/bcmdhd` (`CONFIG_BCMDHD_PCIE=y`, `CONFIG_BCMDHD_MONITOR_MODE=y`)
**Scope:** why monitor-mode capture of *foreign* (not-addressed-to-us) WPA2 EAPOL frames is
truncated to ~96 bytes on this chip, what is and isn't fixable in firmware/driver, and the
delivery paths that *do* yield a complete frame.

This document records a static reverse-engineering effort (d11 PSM microcode + ARM ROM/RAM +
host driver), cross-checked against a cycle-accurate d11 emulator and on-device length probes.
It contains **no exploit/interception tooling** — it documents the hardware datapath, the
mechanism, and the boundary.

---

## 1. Symptom

In monitor mode, a foreign WPA2 4-way-handshake EAPOL frame arrives at the host
**truncated to ~96 bytes** (a fixed ~96 B lbuf, zero-padded past the real on-air ~86–90 B),
dropping exactly the bytes that make a handshake crackable:

| EAPOL field | approx. offset in frame | in the ~96 B? |
|---|---|---|
| 802.11 + LLC/SNAP + 802.1X headers | 0–38 | yes |
| EAPOL-Key: replay counter, **Nonce** | 43–82 | **yes** |
| Key IV / RSC / ID | 83–114 | partially |
| **MIC** (M2/M3) | ~115–130 | **no** |
| **Key Data / RSN PMKID** (M1) | ~133+ | **no** |

This matches the publicly reported, never-resolved nexmon issues
[#461](https://github.com/seemoo-lab/nexmon/issues/461) (this exact device),
[#231](https://github.com/seemoo-lab/nexmon/issues/231) (Galaxy S7), and
[#554](https://github.com/seemoo-lab/nexmon/issues/554).

## 2. Root cause — `splitrx` and the cipher-gated body drain

nexmon author Matthias Schulz named the mechanism in #231 but did not detail it:

> "the d11 core splits each received data frame and only passes the first part to the arm
> firmware and the rest directly to the host … I do not know how to disable it."

We reverse-engineered it to the register level. On the d11 RX path the frame is delivered in
**two stages** (ucode routine at index `102F`):

1. **Stage 1 — lookahead / rxhdr** (`1030`–`1032`): the RXE copy engine
   (`SPR_RXE_RXHDR_OFFSET`/`_LEN` + `RXE_CTL` STARTCOPY) stages a fixed **28-byte** rxhdr and the
   cleartext header prefix toward the host. This is the ~96 B that always arrives.
2. **Stage 2 — "the rest"** (`1034`, `0B98`): the **DAGG** drain (`SPR_DAGG_CTL2 = 7`),
   gated by SHM flag `[0x841] bit0`. Its input FIFO is filled **only by the hardware cipher
   engine**. `SPR_DAGG_LEN` is **HW-produced** (zero ucode writes anywhere in the 6819-instr
   image; reads 0 on plaintext).

The arming of stage 2 diverges at:

- `0B1E jzx 0,14,[0x03,off1]` — tests the **on-air FC.Protected bit** (rx-header FC word,
  HW-written into SHM, the PSM only branches on it). Protected=0 ⇒ `0B85` sets `WEP_CTL`
  algo nibble = 0 (cipher idle). Protected=1 ⇒ key-block at `0B5F`→`0B67` arms a real algo.
- `0AAE jzx 0,7,spr244` (`spr244 = SPR_MHP_QOS`) and the `0AB1`–`0AB3` protected/AMSDU
  branch set the `[0x841]` drain-armed flag and the DAGG offset/length.

**Net:** for a *foreign, unprotected* (Protected=0, no key) EAPOL frame the cipher engine never
runs, the DAGG input FIFO stays empty, stage 2 moves **0 bytes**, and only stage 1's ~96 B
reaches the host. The remaining ~47 B (MIC / PMKID) stay resident in the d11 **receive-FIFO
SRAM** until that FIFO slot is recycled.

Emulator confirmation (`trace_class.py`): beacon, plaintext DATA, and protected EAPOL all
reach the same RX finalizer `0D0C`; plaintext issues only an AMT key-lookup (`cmd=1`) and
delivers ~88 B, while protected additionally issues the body copy (`cmd=7`) and delivers the
full frame.

## 3. Why it is not fixable in firmware on this chip

Every software lever was examined and is closed; the key register-level reasons:

| Lever | Verdict | Reason |
|---|---|---|
| Force the cipher config (force-decrypt / algo-force) | dead (on-device) | HW gates decrypt on Protected=1 **and** a key-table TA match; a foreign frame has neither, so algo stays 0 |
| Raise the lookahead / "96" length | dead | the 96 is not a register — it is where the FIFO→host stream stops because stage 2 never ran; no "96" immediate exists |
| Widen the RXE STARTCOPY (rxhdr) length | dead | stages **metadata** (RxStatus, not the MAC body) into SHM `0x7DD`; over-length clobbers live SHM `0x7EA..0x7ED` |
| Re-purpose the DAGG | dead | no source-select register; `DAGG_LEN` has no ucode write port; input HW-wired to the cipher output FIFO |
| Disable `splitrx` | dead | `_bcmsplitrx` is dongle-only; "the rest to host" **is** the cipher drain — disabling the split cannot conjure a body the cipher never moved |
| ARM-side read of rx-FIFO via **objmem** | dead | the d11 objaddr select field is 4 bits — only **6** selects exist (`brcm80211/brcmsmac/d11.h:594-604`: UCM/SHM/SCR/IHR/RCMTA/SRCHM); **none maps the rx-FIFO**; exhaustively probed on-device |
| ARM-side read via PCIe **backplane** (`dhd_bus_membytes`) | dead | BAR1 reaches only ARM RAM/TCM; BAR0 `si_corereg` is bounded to the core's 4 KB register block (`SI_CORE_SIZE=0x1000`) = the same objaddr ports |
| ARM ROM `dma32diag` FIFO port | dead | no driver/caller in ROM; FIFO already drained before ARM runs; would re-yield the same ~96 B |
| Class-reroute (route DATA via the "management drain") | dead | no FC.type-keyed no-cipher drain exists; "beacon full" is a short-frame / addressed-context artifact |
| AMT/RCMTA "fake AP context" | dead (passive) | an AMT hit only supplies a **key-descriptor**; the body is still moved by the cipher drain keyed by that descriptor's algo. A network whose key we lack ⇒ algo=0 descriptor ⇒ empty FIFO ⇒ still ~96 B. Forcing an Addr1(RA) match also makes the chip **ACK** the frames (active, not passive) |

**The decisive constraint (covers a full firmware rewrite too):** the host-bound receive DMA is
the **autonomous dma64 RX channel** at MMIO **0x220** (rcvcontrol 0x220 / ptr 0x224 / addr 0x228
/ status 0x230). It is descriptor-ring driven and host/ARM-programmed; it has **no SPR alias**
and **zero d11-ucode accesses**. The PSM's instruction set lives in IHR/SPR space (0x400+) and
**physically cannot address** the register that would set a longer transfer length. And the
body is not *presented* to that DMA on the plaintext path anyway — only the cipher drain moves
it into the DMA's view. No ucode/firmware change — patch or full rewrite — can address a
register the ISA does not map nor move data the silicon does not present.

## 4. Delivery paths that DO yield a complete frame

The truncation is a property of *unaddressed* (monitor-cloned) frames, not a fundamental RX
limit. A frame that is genuinely **addressed to us** (passes the d11 address match **and** has a
real per-link context — scb/bsscfg) is delivered **in full**, even when unprotected — this is
how the device receives its own M1 during association. Two consequences:

1. **`WLC_E_EAPOL_MSG` event path.** The firmware event generator `wlc_bss_eapol_event`
   (ROM `0x23cc8`, classifier `0x23d68`, from `wlc_recvdata` RAM `0x1a3068`) **memcpy's the full
   addressed lbuf** into an in-band event (it is scb-gated at `0x23cda`). The driver hook
   `dhd_mon_eapol_reinject` (`dhd_linux.c:2924`, subscribed at `:6273`, dispatched at `:7901`,
   under `CONFIG_BCMDHD_MONITOR_MODE`) rebuilds a complete radiotap+802.11+LLC/SNAP frame and
   injects it into the monitor vif. This delivers full EAPOL for handshakes the local STA
   participates in (e.g. its own association), **no firmware patch**.

2. **AP / participant capture.** When the chip is the AP/SoftAP/GO authenticator's radio, a
   client's M2/M4 are addressed to our BSSID, pass the address match into the keyed finalizer
   (not the truncating `0AAE` divert), have a real scb/bsscfg, and arrive **full** both on the
   AP netdev (`tcpdump`/hostapd) and as a full `WLC_E_EAPOL_MSG`. AP/APSTA is supported on this
   build (`dhd_linux.c:5826-6010`, the `apsta`/`ap_mode` iovars); the stock `fw_bcmdhd.bin`
   already runs a WPA2 authenticator BSS (Android hotspot). Monitor mode is not required;
   capture is on the AP interface. Note this is a **participant/active** model, not passive
   sniffing.

Both are legitimate for **authorized** testing of your own / in-scope networks. Passive capture
of arbitrary foreign handshakes is **not** achievable on the internal chip and needs an
external monitor-capable adapter.

## 5. Single-radio constraint (operational note)

`phy#0` is a single radio. While an AP vif is active on a channel, every other vif (monitor,
P2P) is pinned to that channel — `iw … set channel` on a monitor vif is silently ignored. On
this fullmac driver the channel is owned by firmware (chanspec iovar / AP config), not `iw`.
You can move the whole radio's channel, but you cannot have AP-on-ch-X and monitor-on-ch-Y
simultaneously; that needs a second radio.

## 6. Conclusion

The ~96 B monitor truncation on the BCM4358 is **hardware-enforced**: the full body is moved
out of the rx-FIFO only by the cipher engine's drain, which is HW-gated on Protected=1 + a
key-table TA match, and the receive-DMA length is outside the PSM's addressable register space.
No firmware/ucode/driver change recovers the foreign-plaintext body. Complete EAPOL is available
only for frames the device genuinely participates in (own association → `WLC_E_EAPOL_MSG`;
AP/authenticator → client M2 on the AP interface), or via external monitor hardware.

## 7. References

- nexmon issues [#461](https://github.com/seemoo-lab/nexmon/issues/461),
  [#231](https://github.com/seemoo-lab/nexmon/issues/231),
  [#554](https://github.com/seemoo-lab/nexmon/issues/554)
- d11 objaddr select map: `drivers/net/wireless/brcm80211/brcmsmac/d11.h:594-604`
- driver RX completion / split-rx: `drivers/net/wireless/bcmdhd/dhd_msgbuf.c:2057-2068`
- `BCMSPLITRX` macros: `drivers/net/wireless/bcmdhd/include/bcmdefs.h:306-317`
- EAPOL event reinject: `drivers/net/wireless/bcmdhd/dhd_linux.c:2900-3032,6273,7901`
- AP/APSTA bring-up: `drivers/net/wireless/bcmdhd/dhd_linux.c:5826-6010`
- Authoritative d11 SPR names: nexmon `buildtools/b43-v2/debug/include/spr.inc`

*Static RE; on-device behaviour for the participant paths (§4) should be confirmed with a live
length probe on first use.*
