#!/usr/bin/env bash
# Create a minimal macOS .app bundle and a DMG containing it.
set -euo pipefail

APP_NAME=SecureUSB
APP_DIR=dist/${APP_NAME}.app
BUNDLE_ID=com.example.secureusb

rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Copy the built executable into the .app
cp dist/${APP_NAME} "$APP_DIR/Contents/MacOS/${APP_NAME}"
chmod +x "$APP_DIR/Contents/MacOS/${APP_NAME}"

# Minimal Info.plist
cat > "$APP_DIR/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>${APP_NAME}</string>
  <key>CFBundleExecutable</key>
  <string>${APP_NAME}</string>
  <key>CFBundleIdentifier</key>
  <string>${BUNDLE_ID}</string>
  <key>CFBundleVersion</key>
  <string>1.0</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
</dict>
</plist>
EOF

# Create a DMG
DMG_NAME=${APP_NAME}.dmg
rm -f "$DMG_NAME"
hdiutil create -volname "$APP_NAME" -srcfolder "$APP_DIR" -ov -format UDZO "$DMG_NAME"

echo "Created $DMG_NAME"
