#!/usr/bin/env bash
# Install the BCM4358 monitor-feed probe (bcm4358-feed-probe.c) into the nexmon
# source tree. It BLPatches 0x1a6d28 to record the packet length at the RAM
# monitor feed into the global nexmon_feed_len, which the wl_monitor_radiotap
# probe then smuggles to the kernel. Idempotent.
#
# Usage: bcm4358-install-feed-probe.sh <nexmon-patch-src-dir> <this-dir>
set -euo pipefail
SRCDIR="${1:?usage: $0 <patch .../nexmon/src dir> <nexmon-patches dir>}"
SELFDIR="${2:?usage: $0 <patch .../nexmon/src dir> <nexmon-patches dir>}"
SRC="$SELFDIR/bcm4358-feed-probe.c"
[ -d "$SRCDIR" ] || { echo "::warning::feed-probe: src dir $SRCDIR not found"; exit 0; }
[ -f "$SRC" ]    || { echo "::warning::feed-probe: $SRC not found"; exit 0; }
if [ -f "$SRCDIR/feed_probe.c" ]; then
	echo "feed-probe already installed, nothing to do"; exit 0
fi
cp -f "$SRC" "$SRCDIR/feed_probe.c"
echo "feed-probe: installed $SRCDIR/feed_probe.c (BLPatch 0x1a6d28)"
