"""
Authentication Manager for SecureUSB

Handles password/key authentication for USB device access.
"""

import hashlib
import secrets
import getpass
from typing import Optional, Tuple
from pathlib import Path


class AuthManager:
    """Manages authentication for USB device access."""
    
    def __init__(self, device_path: str):
        """
        Initialize the AuthManager for a specific device.
        
        Args:
            device_path: Path to the USB device
        """
        self.device_path = device_path
        self.salt_length = 32
        self.key_length = 32
    
    def generate_salt(self) -> bytes:
        """Generate a cryptographically secure random salt."""
        return secrets.token_bytes(self.salt_length)
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: User password
            salt: Salt for key derivation
            
        Returns:
            Derived encryption key
        """
        return hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            salt, 
            100000,  # 100,000 iterations
            dklen=self.key_length
        )
    
    def prompt_for_password(self, confirm: bool = False) -> str:
        """
        Securely prompt user for password.
        
        Args:
            confirm: Whether to ask for password confirmation
            
        Returns:
            User password
            
        Raises:
            ValueError: If passwords don't match during confirmation
        """
        password = getpass.getpass("Enter password: ")
        
        if confirm:
            confirm_password = getpass.getpass("Confirm password: ")
            if password != confirm_password:
                raise ValueError("Passwords do not match")
        
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")
        
        return password
    
    def create_auth_data(self, password: str) -> Tuple[bytes, bytes]:
        """
        Create authentication data for a new device.
        
        Args:
            password: User password
            
        Returns:
            Tuple of (salt, derived_key)
        """
        salt = self.generate_salt()
        key = self.derive_key_from_password(password, salt)
        return salt, key
    
    def verify_password(self, password: str, stored_salt: bytes, stored_key_hash: bytes) -> bool:
        """
        Verify password against stored authentication data.
        
        Args:
            password: User provided password
            stored_salt: Stored salt from device metadata
            stored_key_hash: Stored key hash from device metadata
            
        Returns:
            True if password is correct, False otherwise
        """
        derived_key = self.derive_key_from_password(password, stored_salt)
        derived_key_hash = hashlib.sha256(derived_key).digest()
        
        # Use constant-time comparison to prevent timing attacks
        return secrets.compare_digest(derived_key_hash, stored_key_hash)
    
    def get_encryption_key(self, password: str, salt: bytes) -> bytes:
        """
        Get encryption key from password and salt.
        
        Args:
            password: User password
            salt: Salt for key derivation
            
        Returns:
            Encryption key
        """
        return self.derive_key_from_password(password, salt)