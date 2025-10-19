"""
Cryptographic engine for SecureUSB.

Provides encryption and decryption capabilities using AES-256-GCM.
"""
from __future__ import annotations
from typing import Tuple
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Constants
PBKDF2_ITERS = 200_000
KEY_LEN = 32
NONCE_LEN = 12


class CryptoEngine:
    """Cryptographic engine for encryption and decryption operations."""
    
    def __init__(self, key: bytes):
        """
        Initialize the crypto engine with an encryption key.
        
        Args:
            key: 32-byte encryption key for AES-256
            
        Raises:
            ValueError: If key length is not 32 bytes
        """
        if len(key) != KEY_LEN:
            raise ValueError(f"Key must be exactly {KEY_LEN} bytes long")
        self.key = key
        
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
        """
        Derive a 32-byte key from a UTF-8 password and salt.
        
        Args:
            password: User password
            salt: Random salt for key derivation
            iterations: Number of PBKDF2 iterations
            
        Returns:
            Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LEN,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(password.encode("utf-8"))
    
    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data (nonce + ciphertext)
        """
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(NONCE_LEN)
        ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
        return nonce + ciphertext
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            encrypted_data: Encrypted data (nonce + ciphertext)
            
        Returns:
            Decrypted data
            
        Raises:
            ValueError: If encrypted data is invalid
        """
        if len(encrypted_data) < NONCE_LEN:
            raise ValueError("Invalid encrypted data: too short")
            
        nonce = encrypted_data[:NONCE_LEN]
        ciphertext = encrypted_data[NONCE_LEN:]
        
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    
    def encrypt_file(self, input_path: Path, output_path: Path) -> None:
        """
        Encrypt a file and write to output path.
        
        Args:
            input_path: Path to input file
            output_path: Path to encrypted output file
            
        Raises:
            FileNotFoundError: If input file doesn't exist
        """
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
            
        with open(input_path, "rb") as f:
            data = f.read()
            
        encrypted_data = self.encrypt_data(data)
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
    
    def decrypt_file(self, input_path: Path, output_path: Path) -> None:
        """
        Decrypt a file and write to output path.
        
        Args:
            input_path: Path to encrypted input file
            output_path: Path to decrypted output file
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            ValueError: If file cannot be decrypted
        """
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")
            
        with open(input_path, "rb") as f:
            encrypted_data = f.read()
            
        decrypted_data = self.decrypt_data(encrypted_data)
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "wb") as f:
            f.write(decrypted_data)


# Legacy function compatibility
def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
    """Legacy function for backward compatibility."""
    return CryptoEngine.derive_key(password, salt, iterations)


def encrypt_bytes(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Legacy function for backward compatibility."""
    crypto = CryptoEngine(key)
    encrypted = crypto.encrypt_data(data)
    nonce = encrypted[:NONCE_LEN]
    ciphertext = encrypted[NONCE_LEN:]
    return nonce, ciphertext


def decrypt_bytes(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """Legacy function for backward compatibility."""
    crypto = CryptoEngine(key)
    encrypted_data = nonce + ciphertext
    return crypto.decrypt_data(encrypted_data)


def encrypt_file(path: str, key: bytes) -> str:
    """Legacy function for backward compatibility."""
    crypto = CryptoEngine(key)
    input_path = Path(path)
    output_path = Path(path + ".enc")
    crypto.encrypt_file(input_path, output_path)
    return str(output_path)


def decrypt_file(enc_path: str, key: bytes) -> str:
    """Legacy function for backward compatibility."""
    crypto = CryptoEngine(key)
    input_path = Path(enc_path)
    if not enc_path.endswith(".enc"):
        raise ValueError("Expected a .enc file")
    output_path = Path(enc_path[:-4])
    crypto.decrypt_file(input_path, output_path)
    return str(output_path)