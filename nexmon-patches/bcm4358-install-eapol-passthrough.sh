#!/usr/bin/env bash
# Install the BCM4358 monitor-gated EAPOL passthrough patch into the nexmon
# source tree.
#
# Copies bcm4358-eapol-monitor-passthrough.c into the firmware patch's src/
# directory, where the nexmon Makefile ($(wildcard src/*.c)) compiles it into
# the patch region and applies the hook at 0x19ad06. Idempotent.
#
# Effect: in monitor mode (wlc->monitor != 0) the firmware stops intercepting
# 802.1X/EAPOL on RX, so EAPOL flows through the full data path and the
# monitor clone is full length (fixes the 90-byte EAPOL truncation that makes
# captured handshakes uncrackable). Outside monitor mode the original path is
# unchanged, so the phone's own WPA client is unaffected.
#
# Usage: bcm4358-install-eapol-passthrough.sh <nexmon-patch-src-dir> <this-dir>
set -euo pipefail

SRCDIR="${1:?usage: $0 <patch .../nexmon/src dir> <nexmon-patches dir>}"
SELFDIR="${2:?usage: $0 <patch .../nexmon/src dir> <nexmon-patches dir>}"
SRC="$SELFDIR/bcm4358-eapol-monitor-passthrough.c"

if [ ! -d "$SRCDIR" ]; then
	echo "::warning::eapol-passthrough: src dir $SRCDIR not found, skipping"
	exit 0
fi
if [ ! -f "$SRC" ]; then
	echo "::warning::eapol-passthrough: $SRC not found, skipping"
	exit 0
fi

if [ -f "$SRCDIR/eapol_monitor_passthrough.c" ]; then
	echo "eapol-passthrough already installed in $SRCDIR, nothing to do"
	exit 0
fi

cp -f "$SRC" "$SRCDIR/eapol_monitor_passthrough.c"
echo "eapol-passthrough: installed $SRCDIR/eapol_monitor_passthrough.c (hooks 0x19ad06)"
