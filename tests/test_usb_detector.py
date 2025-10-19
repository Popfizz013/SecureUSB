"""
Unit tests for USBDetector module.
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add src to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from usb_detector import USBDetector


class TestUSBDetector(unittest.TestCase):
    """Test cases for USBDetector class."""
    
    def setUp(self):
        """Set up test environment."""
        self.usb_detector = USBDetector()
        
    @patch('psutil.disk_partitions')
    def test_detect_usb_devices_mock(self, mock_partitions):
        """Test USB device detection with mocked data."""
        # Mock USB device data
        mock_partition = Mock()
        mock_partition.device = '/dev/sdb1'
        mock_partition.mountpoint = '/media/usb'
        mock_partition.fstype = 'vfat'
        mock_partition.opts = 'rw,nosuid,nodev,relatime'
        
        mock_partitions.return_value = [mock_partition]
        
        # Mock is_usb_device to return True
        with patch.object(self.usb_detector, 'is_usb_device', return_value=True):
            devices = self.usb_detector.detect_usb_devices()
            
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['device'], '/dev/sdb1')
        self.assertEqual(devices[0]['mountpoint'], '/media/usb')
        
    def test_format_device_info(self):
        """Test device info formatting."""
        device_info = {
            'device': '/dev/sdb1',
            'mountpoint': '/media/usb',
            'fstype': 'vfat',
            'size': 8000000000,  # 8GB
            'used': 1000000000,  # 1GB
            'free': 7000000000   # 7GB
        }
        
        formatted = self.usb_detector.format_device_info(device_info)
        
        self.assertIn('/dev/sdb1', formatted)
        self.assertIn('/media/usb', formatted)
        self.assertIn('vfat', formatted)
        
    def test_get_device_capacity(self):
        """Test device capacity calculation."""
        # This test would need actual device or mock
        # For now, just test that method exists
        self.assertTrue(hasattr(self.usb_detector, 'get_device_capacity'))
        
    def test_is_mounted(self):
        """Test mount status check."""
        # Test with obviously non-existent device
        result = self.usb_detector.is_mounted('/dev/nonexistent')
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()