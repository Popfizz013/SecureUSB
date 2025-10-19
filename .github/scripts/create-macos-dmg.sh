#!/usr/bin/env bash
# Usage: create-macos-dmg.sh <dist_dir> <tag>
set -euo pipefail
DIST_DIR=${1:-dist}
TAG=${2:-dev}
DMG_NAME="SecureUSB-macos-${TAG}.dmg"

if [ ! -d "$DIST_DIR" ]; then
  echo "Dist dir $DIST_DIR not found"
  exit 1
fi

STAGE=$(mktemp -d)
cp -R "$DIST_DIR"/* "$STAGE"/

echo "Creating DMG $DMG_NAME from $STAGE"
hdiutil create -volname "SecureUSB" -srcfolder "$STAGE" -ov -format UDZO "$DMG_NAME"

mv "$DMG_NAME" "$DIST_DIR/"

rm -rf "$STAGE"
echo "DMG created at $DIST_DIR/$DMG_NAME"
