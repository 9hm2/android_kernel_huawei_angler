# AnyKernel3 Ramdisk Mod Script
# osm0sis @ xda-developers
#
# Angler (Nexus 6P) NetHunter kernel + nexmon monitor-mode firmware installer.
# The kernel half flashes Image.gz-dtb into the boot image; the install hook
# below additionally drops the nexmon-patched fw_bcmdhd.bin into the firmware
# directory so native monitor mode / injection work end to end.

## AnyKernel setup
# begin properties
properties() { '
kernel.string=NetHunter angler kernel (Re4son) + nexmon monitor firmware
do.devicecheck=1
do.modules=0
do.systemless=1
do.cleanup=1
do.cleanuponabort=1
device.name1=angler
device.name2=Nexus 6P
device.name3=Huawei Nexus 6P
device.name4=
device.name5=
supported.versions=
supported.patchlevels=
'; } # end properties

# shell variables
block=/dev/block/bootdevice/by-name/boot;
is_slot_device=0;
ramdisk_compression=auto;
patch_vbmeta_flag=auto;


## AnyKernel methods (DO NOT CHANGE)
# import patching functions/variables - see for reference
. tools/ak3-core.sh;


## AnyKernel install
split_boot;

# no ramdisk modifications needed - we only replace the kernel
flash_boot;


## nexmon firmware install
# Copy the nexmon-patched fw_bcmdhd.bin shipped alongside this zip into the
# firmware directory. On angler /vendor is part of /system (pre-Treble), so we
# try the real /vendor mountpoint first and fall back to /system/vendor.
install_nexmon_firmware() {
  # AnyKernel3 extracts the zip into $AKHOME (older AK builds used $home);
  # fall back gracefully so the bundled firmware is found either way.
  local akroot="${AKHOME:-$home}";
  local src="$akroot/firmware/fw_bcmdhd.bin";
  local fwdir="" dst="";

  if [ ! -f "$src" ]; then
    ui_print " "; ui_print "! nexmon firmware not bundled - skipping firmware install";
    return 0;
  fi

  ui_print " "; ui_print "Installing nexmon firmware...";

  # Make sure the relevant partitions are mounted read-write.
  mount /system 2>/dev/null;
  mount /vendor 2>/dev/null;
  mount -o remount,rw /system 2>/dev/null;
  mount -o remount,rw /vendor 2>/dev/null;
  mount -o remount,rw / 2>/dev/null;

  # Resolve the firmware directory that the bcmdhd driver loads from
  # (CONFIG_BCMDHD_FW_PATH="/vendor/firmware/fw_bcmdhd.bin").
  if [ -d /vendor/firmware ]; then
    fwdir=/vendor/firmware;
  elif [ -d /system/vendor/firmware ]; then
    fwdir=/system/vendor/firmware;
  else
    mkdir -p /system/vendor/firmware 2>/dev/null;
    fwdir=/system/vendor/firmware;
  fi
  dst="$fwdir/fw_bcmdhd.bin";

  # Keep a one-time backup of the stock firmware so the change is reversible.
  if [ -f "$dst" ] && [ ! -f "$dst.stock" ]; then
    cp -f "$dst" "$dst.stock";
    ui_print "  backed up stock firmware -> $dst.stock";
  fi

  cp -f "$src" "$dst";
  chmod 0644 "$dst";
  chown 0.0 "$dst" 2>/dev/null;
  ui_print "  installed -> $dst";

  # logstrs.bin (if bundled) lets the dhd driver translate a dongle-trap epc
  # into a firmware function name, so injection-flood traps are diagnosable.
  if [ -f "$akroot/firmware/logstrs.bin" ]; then
    cp -f "$akroot/firmware/logstrs.bin" "$fwdir/logstrs.bin";
    chmod 0644 "$fwdir/logstrs.bin";
    chown 0.0 "$fwdir/logstrs.bin" 2>/dev/null;
    ui_print "  installed -> $fwdir/logstrs.bin";
  fi

  umount /vendor 2>/dev/null;
  umount /system 2>/dev/null;
}

install_nexmon_firmware;

## end install
