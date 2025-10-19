#!/usr/bin/env bash
set -euo pipefail
echo "Running build on macOS (macos-latest)"

# CONFIGURE: change these if your entry filenames are different
CLI_ENTRY=${CLI_ENTRY:-src/main.py}
GUI_ENTRY=${GUI_ENTRY:-src/main.py}
APP_NAME="SecureUSB"
DIST_DIR=dist

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

python3 -m pip install --upgrade pip setuptools wheel
if [ -f requirements.txt ]; then
  pip3 install -r requirements.txt
fi
pip3 install pyinstaller

# Build CLI
echo "Building CLI ($CLI_ENTRY)"
pyinstaller --onefile --name secureusb-cli "$CLI_ENTRY"
cp dist/secureusb-cli "$DIST_DIR/" || true

# Build GUI (.app)
if [ -f "$GUI_ENTRY" ]; then
  echo "Building GUI ($GUI_ENTRY) as macOS app bundle"
  pyinstaller --noconfirm --windowed --name SecureUSB "$GUI_ENTRY"
  if [ -d "dist/SecureUSB.app" ]; then
    cp -R "dist/SecureUSB.app" "$DIST_DIR/"
  else
    cp dist/SecureUSB "$DIST_DIR/" || true
  fi
fi

# Create .dmg using helper
.github/scripts/create-macos-dmg.sh "$DIST_DIR" "${TAG:-dev}"

# Optional notarization: set APPLE_API_KEY_B64, APPLE_KEY_ID and APPLE_ISSUER_ID
if [ ! -z "${APPLE_API_KEY_B64:-}" ]; then
  echo "Notarization: decoding API key"
  echo "$APPLE_API_KEY_B64" | base64 -d > /tmp/secureusb_key.p8
  # Example (commented): xcrun notarytool submit path/to/dmg --key /tmp/secureusb_key.p8 --key-id "$APPLE_KEY_ID" --issuer "$APPLE_ISSUER_ID" --wait
  echo "Notarization steps are placeholders. Add notarytool commands when ready with Apple API key."
fi

echo "macOS build finished. Artifacts in $DIST_DIR/"
