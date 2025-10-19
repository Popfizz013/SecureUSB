"""
Unit tests for AuthManager module.
"""

import unittest
import sys
from pathlib import Path
from unittest.mock import patch

# Add src to path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from auth_manager import AuthManager


class TestAuthManager(unittest.TestCase):
    """Test cases for AuthManager class."""
    
    def setUp(self):
        """Set up test environment."""
        self.auth_manager = AuthManager("/dev/test")
        self.test_password = "test_password_123"
        
    def test_generate_salt(self):
        """Test salt generation."""
        salt1 = self.auth_manager.generate_salt()
        salt2 = self.auth_manager.generate_salt()
        
        # Check salt length
        self.assertEqual(len(salt1), 32)
        self.assertEqual(len(salt2), 32)
        
        # Check salts are different
        self.assertNotEqual(salt1, salt2)
        
    def test_derive_key_from_password(self):
        """Test key derivation from password."""
        salt = b'test_salt_32_bytes_long_for_test'
        
        key1 = self.auth_manager.derive_key_from_password(self.test_password, salt)
        key2 = self.auth_manager.derive_key_from_password(self.test_password, salt)
        
        # Same password and salt should produce same key
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)  # 32 bytes for AES-256
        
        # Different salt should produce different key
        different_salt = b'different_salt_32_bytes_long_test'
        key3 = self.auth_manager.derive_key_from_password(self.test_password, different_salt)
        self.assertNotEqual(key1, key3)
        
    def test_create_auth_data(self):
        """Test creation of authentication data."""
        salt, key = self.auth_manager.create_auth_data(self.test_password)
        
        self.assertEqual(len(salt), 32)
        self.assertEqual(len(key), 32)
        
        # Verify key can be recreated with same password and salt
        recreated_key = self.auth_manager.derive_key_from_password(self.test_password, salt)
        self.assertEqual(key, recreated_key)
        
    def test_verify_password(self):
        """Test password verification."""
        import hashlib
        
        salt, key = self.auth_manager.create_auth_data(self.test_password)
        key_hash = hashlib.sha256(key).digest()
        
        # Correct password should verify
        self.assertTrue(
            self.auth_manager.verify_password(self.test_password, salt, key_hash)
        )
        
        # Wrong password should not verify
        self.assertFalse(
            self.auth_manager.verify_password("wrong_password", salt, key_hash)
        )
        
    @patch('getpass.getpass')
    def test_prompt_for_password(self, mock_getpass):
        """Test password prompting."""
        mock_getpass.return_value = self.test_password
        
        password = self.auth_manager.prompt_for_password()
        self.assertEqual(password, self.test_password)
        
    @patch('getpass.getpass')
    def test_prompt_for_password_with_confirmation(self, mock_getpass):
        """Test password prompting with confirmation."""
        mock_getpass.side_effect = [self.test_password, self.test_password]
        
        password = self.auth_manager.prompt_for_password(confirm=True)
        self.assertEqual(password, self.test_password)
        
    @patch('getpass.getpass')
    def test_prompt_for_password_mismatch(self, mock_getpass):
        """Test password confirmation mismatch."""
        mock_getpass.side_effect = [self.test_password, "different_password"]
        
        with self.assertRaises(ValueError):
            self.auth_manager.prompt_for_password(confirm=True)
            
    @patch('getpass.getpass')
    def test_prompt_for_password_too_short(self, mock_getpass):
        """Test password too short validation."""
        mock_getpass.return_value = "short"
        
        with self.assertRaises(ValueError):
            self.auth_manager.prompt_for_password()


if __name__ == '__main__':
    unittest.main()