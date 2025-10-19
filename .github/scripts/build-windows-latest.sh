#!/usr/bin/env bash
set -euo pipefail
echo "Running build on Windows (windows-latest) - using Bash shell."

# CONFIGURE: change these if your entry filenames are different
CLI_ENTRY=${CLI_ENTRY:-src/main.py}
GUI_ENTRY=${GUI_ENTRY:-src/main.py}
DIST_DIR=dist
PYTHON=python

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Install Python deps
$PYTHON -m pip install --upgrade pip setuptools wheel
if [ -f requirements.txt ]; then
  $PYTHON -m pip install -r requirements.txt
fi
$PYTHON -m pip install pyinstaller

# Build CLI
echo "Building CLI ($CLI_ENTRY)"
$PYTHON -m PyInstaller --onefile --name secureusb-cli "$CLI_ENTRY"
cp dist/secureusb-cli.exe "$DIST_DIR/" || true

# Build GUI (windowed)
if [ -f "$GUI_ENTRY" ]; then
  echo "Building GUI ($GUI_ENTRY)"
  $PYTHON -m PyInstaller --noconfirm --windowed --onefile --name SecureUSB "$GUI_ENTRY"
  cp dist/SecureUSB.exe "$DIST_DIR/" || true
fi

# Optional: create NSIS installer (uses makensis present on windows-latest)
if command -v makensis >/dev/null 2>&1 && [ -f .github/installer/secureusb_installer.iss ]; then
  echo "Creating NSIS installer"
  makensis /V2 .github/installer/secureusb_installer.iss
  if [ -f "SecureUSB-Installer.exe" ]; then
    mv SecureUSB-Installer.exe "$DIST_DIR/"
  fi
else
  echo "makensis not found or installer script missing; skipping NSIS packaging."
fi

# Optional code signing: set these GitHub Secrets to enable signing
# WINDOWS_PFX_B64 (base64 of .pfx file) and WINDOWS_PFX_PASSWORD
if [ ! -z "${WINDOWS_PFX_B64:-}" ]; then
  echo "Decoding PFX and signing binaries"
  echo "$WINDOWS_PFX_B64" | base64 -d > cert.pfx
  if command -v signtool >/dev/null 2>&1; then
    for f in "$DIST_DIR"/*.exe; do
      echo "Signing $f"
      signtool sign /f cert.pfx /p "$WINDOWS_PFX_PASSWORD" /tr http://timestamp.digicert.com /td sha256 /fd sha256 "$f" || true
    done
  else
    echo "signtool not found on runner; consider using osslsigncode or sign on your own machine."
  fi
fi

echo "Windows build finished. Artifacts in $DIST_DIR/"
