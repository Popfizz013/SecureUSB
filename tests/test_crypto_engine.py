"""
Unit tests for CryptoEngine module.
"""

import unittest
import tempfile
import os
from pathlib import Path
import sys

# Add src to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from crypto_engine import CryptoEngine


class TestCryptoEngine(unittest.TestCase):
    """Test cases for CryptoEngine class."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_key = b'test_key_32_bytes_long_for_aes256'  # 32 bytes for AES-256
        self.crypto_engine = CryptoEngine(self.test_key)
        
    def test_key_validation(self):
        """Test key length validation."""
        # Valid key (32 bytes)
        valid_key = b'a' * 32
        engine = CryptoEngine(valid_key)
        self.assertIsInstance(engine, CryptoEngine)
        
        # Invalid key (too short)
        with self.assertRaises(ValueError):
            CryptoEngine(b'short_key')
            
    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption."""
        test_data = b"This is test data for encryption"
        
        # Encrypt data
        encrypted_data = self.crypto_engine.encrypt_data(test_data)
        self.assertNotEqual(encrypted_data, test_data)
        self.assertGreater(len(encrypted_data), len(test_data))
        
        # Decrypt data
        decrypted_data = self.crypto_engine.decrypt_data(encrypted_data)
        self.assertEqual(decrypted_data, test_data)
        
    def test_encrypt_decrypt_empty_data(self):
        """Test encryption/decryption of empty data."""
        empty_data = b""
        
        encrypted = self.crypto_engine.encrypt_data(empty_data)
        decrypted = self.crypto_engine.decrypt_data(encrypted)
        
        self.assertEqual(decrypted, empty_data)
        
    def test_encrypt_decrypt_file(self):
        """Test file encryption and decryption."""
        test_content = b"This is test file content for encryption testing"
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(test_content)
            temp_file_path = Path(temp_file.name)
            
        encrypted_path = None
        decrypted_path = None
        
        try:
            # Encrypt file
            encrypted_path = temp_file_path.with_suffix('.encrypted')
            self.crypto_engine.encrypt_file(temp_file_path, encrypted_path)
            
            self.assertTrue(encrypted_path.exists())
            
            # Verify encrypted content is different
            with open(encrypted_path, 'rb') as f:
                encrypted_content = f.read()
            self.assertNotEqual(encrypted_content, test_content)
            
            # Decrypt file
            decrypted_path = temp_file_path.with_suffix('.decrypted')
            self.crypto_engine.decrypt_file(encrypted_path, decrypted_path)
            
            # Verify decrypted content matches original
            with open(decrypted_path, 'rb') as f:
                decrypted_content = f.read()
            self.assertEqual(decrypted_content, test_content)
            
        finally:
            # Cleanup
            for path in [temp_file_path, encrypted_path, decrypted_path]:
                if path and path.exists():
                    path.unlink()
                    
    def test_invalid_encrypted_data(self):
        """Test decryption of invalid data."""
        invalid_data = b"This is not encrypted data"
        
        with self.assertRaises(ValueError):
            self.crypto_engine.decrypt_data(invalid_data)


if __name__ == '__main__':
    unittest.main()