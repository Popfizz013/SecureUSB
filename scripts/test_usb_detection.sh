#!/bin/bash
# Quick test runner for USB detection functionality

set -e

echo "Testing USB detection functionality..."

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate || source venv/Scripts/activate
    echo "Virtual environment activated"
fi

echo ""
echo "=== Testing USB Detector Module ==="
python3 -c "
import sys
sys.path.append('src')
from usb_detector import USBDetector

print('Creating USB detector...')
detector = USBDetector(verbose=True)

print('Detecting USB devices...')
devices = detector.detect_usb_devices()

print(f'Found {len(devices)} device(s)')
for i, device in enumerate(devices, 1):
    print(f'Device {i}: {device[\"device\"]} at {device[\"mountpoint\"]}')
    print(f'  Type: {device[\"fstype\"]}, Size: {device[\"size\"] / (1024**3):.2f} GB')
"

echo ""
echo "=== Testing CLI Interface ==="
python3 src/ui/cli_interface.py --status

echo ""
echo "=== Running Unit Tests ==="
if command -v pytest &> /dev/null; then
    pytest tests/ -v
else
    python3 -m unittest discover tests/ -v
fi

echo ""
echo "USB detection testing complete!"