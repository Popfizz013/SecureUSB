"""
Unit tests for MetadataManager module.
"""

import unittest
import tempfile
import json
import sys
from pathlib import Path

# Add src to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from metadata import MetadataManager


class TestMetadataManager(unittest.TestCase):
    """Test cases for MetadataManager class."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.device_path = "/dev/test"
        self.metadata_manager = MetadataManager(self.device_path, str(self.temp_dir))
        
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        
    def test_create_metadata(self):
        """Test metadata creation."""
        owner_id = "test_user"
        salt = b"test_salt_32_bytes_long_for_test"
        key_hash = b"test_key_hash_32_bytes_long_test"
        
        metadata = self.metadata_manager.create_metadata(owner_id, salt, key_hash)
        
        self.assertEqual(metadata['device_path'], self.device_path)
        self.assertEqual(metadata['owner_id'], owner_id)
        self.assertIn('created_at', metadata)
        self.assertIn('last_accessed', metadata)
        
    def test_save_and_load_metadata(self):
        """Test saving and loading metadata."""
        owner_id = "test_user"
        salt = b"test_salt_32_bytes_long_for_test"
        key_hash = b"test_key_hash_32_bytes_long_test"
        
        # Create and save metadata
        metadata = self.metadata_manager.create_metadata(owner_id, salt, key_hash)
        success = self.metadata_manager.save_metadata(metadata)
        self.assertTrue(success)
        
        # Load metadata
        loaded_metadata = self.metadata_manager.load_metadata()
        self.assertIsNotNone(loaded_metadata)
        self.assertEqual(loaded_metadata['owner_id'], owner_id)
        
    def test_metadata_file_path(self):
        """Test metadata file path generation."""
        expected_filename = "dev_test.secureusb"
        expected_path = self.temp_dir / expected_filename
        
        actual_path = self.metadata_manager.get_metadata_file_path()
        self.assertEqual(actual_path, expected_path)
        
    def test_metadata_exists(self):
        """Test metadata existence check."""
        # Should not exist initially
        self.assertFalse(self.metadata_manager.metadata_exists())
        
        # Create metadata
        owner_id = "test_user"
        salt = b"test_salt"
        key_hash = b"test_key_hash"
        
        metadata = self.metadata_manager.create_metadata(owner_id, salt, key_hash)
        self.metadata_manager.save_metadata(metadata)
        
        # Should exist now
        self.assertTrue(self.metadata_manager.metadata_exists())
        
    def test_update_last_accessed(self):
        """Test updating last accessed time."""
        owner_id = "test_user"
        salt = b"test_salt"
        key_hash = b"test_key_hash"
        
        # Create and save initial metadata
        metadata = self.metadata_manager.create_metadata(owner_id, salt, key_hash)
        self.metadata_manager.save_metadata(metadata)
        
        original_time = metadata['last_accessed']
        
        # Wait a moment and update
        import time
        time.sleep(0.1)
        
        success = self.metadata_manager.update_last_accessed()
        self.assertTrue(success)
        
        # Load updated metadata
        updated_metadata = self.metadata_manager.load_metadata()
        self.assertGreater(updated_metadata['last_accessed'], original_time)
        
    def test_invalid_metadata_file(self):
        """Test handling of invalid metadata file."""
        # Create invalid JSON file
        metadata_path = self.metadata_manager.get_metadata_file_path()
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(metadata_path, 'w') as f:
            f.write("invalid json content")
        
        # Should return None for invalid file
        metadata = self.metadata_manager.load_metadata()
        self.assertIsNone(metadata)


if __name__ == '__main__':
    unittest.main()