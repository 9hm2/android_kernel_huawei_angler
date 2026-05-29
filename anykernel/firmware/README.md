# Bundled firmware

This directory is where the build workflow drops the **nexmon-patched**
`fw_bcmdhd.bin` before zipping the AnyKernel3 package. The flashing script
(`../anykernel.sh`) copies it into the device firmware directory
(`/vendor/firmware/fw_bcmdhd.bin`, which on angler lives under
`/system/vendor/firmware`) and keeps a one-time backup of the stock firmware as
`fw_bcmdhd.bin.stock`.

The blob is **not** committed to the repository. It is produced from source by
`.github/workflows/build-kernel-nexmon.yml` (the nexmon firmware is built in
CI for the `bcm4358` chip of the Nexus 6P) and added here at build time only.
