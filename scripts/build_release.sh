#!/usr/bin/env bash
# Build a one-file executable using PyInstaller (macOS / Linux)
set -euo pipefail

echo "Installing Python deps..."
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

echo "Cleaning previous builds..."
rm -rf build dist __pycache__

echo "Building SecureUSB..."
pyinstaller --clean --onefile --name SecureUSB src/main.py

ARTIFACT=dist/SecureUSB
if [ -f "$ARTIFACT" ]; then
  echo "Build complete: $ARTIFACT"
  if [ -d "$HOME/Desktop" ]; then
    cp "$ARTIFACT" "$HOME/Desktop/"
    echo "Copied to Desktop"
  fi
else
  echo "Build failed: artifact not found"
  exit 1
fi
