# Nexus 6P (BCM4358) — on-device measurement run (BUILD 1: instrumentation)

**Audience:** the Claude instance running in the phone's terminal (root, Kali
chroot available). Goal of THIS run: *measure*, on the live d11 chip, the DAGG
body-copy bookkeeping that controls how many bytes of a received frame reach the
host. This replaces an offline emulator that proved unreliable. **This build does
NOT change Wi-Fi behaviour** (the kick gate is replicated byte-for-byte); it only
stamps internal d11 state into spare shared-memory so we can read it out.

Write a single plain-text report to `/sdcard/Download/measure_report.txt` and tell
the user it is ready to upload back.

## Background (why we read these)
A foreign WPA2 EAPOL frame is truncated to ~86 bytes on capture, losing the Key
MIC, so handshakes won't crack. Encrypted/protected foreign frames arrive FULL.
The difference is the d11 "body copy" (DAGG cmd=7): it fires only on the protected
path. We added instrumentation that, for every received data frame, stamps into
SHM words `0x890..0x896` the live values the body copy uses. By reading them for a
known-FULL (protected) frame we learn the exact parameters the upcoming fix must
reproduce for plaintext, and we confirm the byte-count never goes wild (safety).

## 0. Get the firmware on the device
The build publishes a GitHub release with `fw_bcmdhd.bin` (+ `fw_bcmdhd.bin.md5`)
and `ucmread.c` as standalone assets, and a flashable AnyKernel zip.

- Easiest: flash the AnyKernel zip in TWRP (kernel + firmware together), OR
- Install the standalone firmware from a root shell:
  ```
  mount -o remount,rw /vendor 2>/dev/null
  curl -L -o /vendor/firmware/fw_bcmdhd.bin <release_url>/fw_bcmdhd.bin
  sync
  md5sum /vendor/firmware/fw_bcmdhd.bin     # MUST equal fw_bcmdhd.bin.md5 from the release
  ```
Reboot (or reload the wlan module) so the new firmware is live. Record `uname -r`
and the md5 in the report.

## 1. Build the read-back tool
```
curl -L -o /tmp/ucmread.c <release_url>/ucmread.c
gcc -O2 -o /tmp/ucmread /tmp/ucmread.c       # use the Kali chroot gcc if needed
```
`ucmread` usage: `ucmread <ifname> <hex_offset> <len> [cmd]`
- `cmd 0x600` = read live d11 UCM (microcode) bytes; `UCM[x] == ucode.bin[x]`.
- `cmd 0x601` = EAPOL RX diagnostic bucket A; `cmd 0x602` = full-DATA bucket B.
- `cmd 0x603` = read d11 SHM words; `<hex_offset>` is the SHM **byte** address
  (= word*2), `<len>` is the number of 16-bit words.

## 2. Confirm the instrumentation is actually live in the d11
```
ucmread wlan0 0x0    8            # anchor, MUST be: 4e10000360bc0100
ucmread wlan0 0x5ca8 8            # 0B95 hook,  expect: 3114f0025e680000
ucmread wlan0 0xa188 8            # stamp slot, expect: 9008008b49b00000
ucmread wlan0 0xa1c8 8            # gate copy,  expect: 960bf0025e680000
```
If the anchor is right but the others read the OLD bytes (`990b000721000200` /
`8017009705b00000` / `3c140003de6a0000`), the patched ucode did NOT reach the
chip — STOP and report that (firmware not actually flashed / wrong file). Put all
four lines verbatim in the report.

## 3. Passive capture of a real 4-way handshake (monitor only, NOT associated)
Use the internal chip in monitor mode. Do not associate to the target.
```
airmon-ng start wlan0    # or: iw dev wlan0 set type monitor; ifconfig wlan0 up
# pick a nearby AP+client you are authorised to test; lock the channel:
airodump-ng -c <ch> --bssid <AP_MAC> -w /sdcard/Download/cap wlan0mon &
# force a reauth so M1..M4 fly (authorised test network only):
aireplay-ng -0 3 -a <AP_MAC> -c <CLIENT_MAC> wlan0mon
# let it run ~20-30s with normal traffic so plenty of PROTECTED data frames pass
```
Stop airodump after you have the handshake (or after ~30s).

## 4. Read the diagnostics IMMEDIATELY after capture (order matters)
```
echo "== SHM DAGG stamp (words 0x890..0x897) =="
ucmread wlan0 0x1120 8 0x603       # 0x890..0x897
echo "== wide SHM window (fallback, words 0x880..0x89F) =="
ucmread wlan0 0x1100 32 0x603
echo "== diag bucket A (last EAPOL frame) =="
ucmread wlan0 0 256 0x601
echo "== diag bucket B (largest DATA frame) =="
ucmread wlan0 0 256 0x602
```
Capture ALL of this output verbatim into the report.

### How to interpret (include your interpretation in the report)
SHM read at `0x1120` returns 8 little-endian 16-bit words:
```
word0 = [0x890] spr262  (DAGG source offset)
word1 = [0x891] [0x86B] (body total length)
word2 = [0x892] bytes-to-copy = [0x86B]-spr262   <-- must be POSITIVE & sane (< ~1600)
word3 = [0x893] spr00c  (RXE_RXCNT bytes copied so far)
word4 = [0x894] [0x841] : bit0 = kick-gate, bit1 = PATH TAG (1=protected, 0=unprotected)
word5 = [0x895] [0x838] RxFrameSize (delivered length so far)
word6 = [0x896] spr211  (framelen)
```
- If `word4` bit1 = 1 (protected frame was last): note spr262, [0x86B], framelen.
  We expect `spr262 ≈ machdr_off + 0x10` and `[0x86B] ≈ framelen + 0x2`. Report the
  actual numbers and `framelen - spr262` (this is the plaintext body offset the fix
  will use).
- `word2` (bytes-to-copy) is the key SAFETY number: confirm it is positive and not
  absurd (e.g. not 0xFFxx). Report its value.

diag buckets A/B layout (256 bytes each):
```
[0..1]  match count (LE16)
[2..3]  p->len = delivered frame length (LE16)   <-- 86 for truncated EAPOL
[4..35] rxhdr[0..31]  (RxFrameSize@0, RxStatus1@4, RxStatus2@6)
[36..]  raw 802.11 frame from offset 0 (FC, addrs, LLC 88 8e, EAPOL body)
```
In the report, for bucket A give: count, p->len, the 32-byte rxhdr, and whether the
frame bytes contain `88 8e` and where the EAPOL body ends (i.e. is the Key MIC,
16 bytes near frame offset ~113, present or zero). For bucket B give: count, p->len
(should be large, a full frame), and the 32-byte rxhdr — so we can DIFF the two
rxhdrs.

## 5. Does the handshake crack as-is? (expected: NO on this build)
```
which hcxpcapngtool && hcxpcapngtool /sdcard/Download/cap-01.cap \
   -o /sdcard/Download/hash.22000 ; cat /sdcard/Download/hash.22000 2>/dev/null
```
Report whether any `WPA*02*`/`WPA*01*` line was produced (it should NOT be on the
instrumentation build — that is the fix build, next).

## 6. Write the report
Save everything above to `/sdcard/Download/measure_report.txt`:
- uname -r, fw md5
- the 4 ucode verify lines (step 2)
- the raw SHM reads (step 4) + your decoded interpretation
- bucket A and bucket B raw + decoded (p->len, rxhdr, MIC present?)
- the hcxpcapngtool result
Then tell the user the report is at `/sdcard/Download/measure_report.txt`, ready to
upload back here.

---
*Build 2 (the actual fix that delivers the full EAPOL incl. Key MIC) is staged and
will be enabled once these measurements confirm the body-copy parameters and that
`bytes-to-copy` stays sane.*
