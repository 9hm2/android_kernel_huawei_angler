#!/usr/bin/env bash
# Install the BCM4358 free() NULL-guard patch into the nexmon source tree.
#
# Copies bcm4358-free-null-guard.c into the firmware patch's src/ directory,
# where the nexmon Makefile ($(wildcard src/*.c)) compiles it into the patch
# region and applies the hook at 0x18234c. Idempotent.
#
# Usage: bcm4358-install-free-guard.sh <nexmon-patch-src-dir> <this-script-dir>
set -euo pipefail

SRCDIR="${1:?usage: $0 <patch .../nexmon/src dir> <nexmon-patches dir>}"
SELFDIR="${2:?usage: $0 <patch .../nexmon/src dir> <nexmon-patches dir>}"
GUARD="$SELFDIR/bcm4358-free-null-guard.c"

if [ ! -d "$SRCDIR" ]; then
	echo "::warning::free-guard: src dir $SRCDIR not found, skipping"
	exit 0
fi
if [ ! -f "$GUARD" ]; then
	echo "::warning::free-guard: $GUARD not found, skipping"
	exit 0
fi

if [ -f "$SRCDIR/free_null_guard.c" ]; then
	echo "free-guard already installed in $SRCDIR, nothing to do"
	exit 0
fi

cp -f "$GUARD" "$SRCDIR/free_null_guard.c"
echo "free-guard: installed $SRCDIR/free_null_guard.c (hooks free() at 0x18234c)"
