"""
Improved AuthManager for SecureUSB

Features added:
- Configurable PBKDF2 parameters (iterations, hash)
- Metadata read/write (atomic) to JSON on-device with base64 encoding for bytes
- Password prompt with optional visible input
- Password change helper
- Safe verification using constant-time comparison
- Helpful logging and clear exceptions

Usage:
- Put this file in `src/` alongside `cli_auth.py` while developing.
- Run tests by `cd src` then `python auth_manager.py` (demo in __main__).

"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Tuple

# Windows-specific imports for file hiding
if sys.platform == "win32":
    try:
        import ctypes
        from ctypes import wintypes
    except ImportError:
        ctypes = None

try:
    import getpass
except Exception:  # pragma: no cover - fallback for non-interactive environments
    getpass = None

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

METADATA_FILENAME = ".secureusb_meta.json"


def _b64_encode(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64_decode(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _hide_file_windows(file_path: Path) -> bool:
    """Hide a file on Windows by setting the hidden attribute.
    
    Returns:
        True if successful, False otherwise
    """
    if sys.platform != "win32" or ctypes is None:
        return False
    
    try:
        # FILE_ATTRIBUTE_HIDDEN = 2
        FILE_ATTRIBUTE_HIDDEN = 2
        ret = ctypes.windll.kernel32.SetFileAttributesW(str(file_path), FILE_ATTRIBUTE_HIDDEN)
        return bool(ret)
    except Exception as e:
        logger.debug(f"Failed to hide file on Windows: {e}")
        return False


@dataclass
class KdfMeta:
    kdf: str
    hash_name: str
    iterations: int
    salt_length: int
    key_length: int


class AuthManager:
    """Manages authentication metadata and key derivation for a USB device.

    Metadata JSON schema (example):
    {
        "version": 1,
        "kdf": "pbkdf2",
        "hash_name": "sha256",
        "iterations": 200000,
        "salt": "BASE64...",
        "key_hash": "BASE64...",
        "created_at": "2025-10-19T12:34:56Z"
    }
    """

    def __init__(self, device_path: str, *, iterations: int = 200000, salt_length: int = 32, key_length: int = 32, hash_name: str = "sha256"):
        self.device_path = Path(device_path)
        self.iterations = int(iterations)
        self.salt_length = int(salt_length)
        self.key_length = int(key_length)
        self.hash_name = hash_name

    def _meta_path(self, metadata_file: Optional[Path]) -> Path:
        if metadata_file:
            return Path(metadata_file)
        # default: metadata lives at the root of the device_path
        return (self.device_path / METADATA_FILENAME).resolve()

    def generate_salt(self) -> bytes:
        return secrets.token_bytes(self.salt_length)

    def derive_key_from_password(self, password: str, salt: bytes, *, iterations: Optional[int] = None) -> bytes:
        iterations = iterations or self.iterations
        if not isinstance(password, str):
            raise TypeError("password must be a string")
        return hashlib.pbkdf2_hmac(self.hash_name, password.encode("utf-8"), salt, int(iterations), dklen=self.key_length)

    def prompt_for_password(self, confirm: bool = False, visible: bool = False) -> str:
        """Prompt user for a password. Use visible=True to echo input (for debugging/testing).

        Raises ValueError for invalid passwords during confirmation or length checks.
        """
        if visible:
            prompt_fn = input
        else:
            if getpass is None:
                # fallback to visible if getpass not available
                prompt_fn = input
            else:
                prompt_fn = getpass.getpass

        password = prompt_fn("Enter password: ")
        
        if confirm:
            confirm_password = prompt_fn("Confirm password: ")
            if password != confirm_password:
                raise ValueError("Passwords do not match")

        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")

        return password

    def create_auth_data(self, password: str) -> Dict[str, object]:
        """Create metadata dict for a new password. Caller should store this to the device."""
        salt = self.generate_salt()
        key = self.derive_key_from_password(password, salt)
        key_hash = hashlib.sha256(key).digest()

        meta = {
            "version": 1,
            "kdf": "pbkdf2",
            "hash_name": self.hash_name,
            "iterations": self.iterations,
            "salt": _b64_encode(salt),
            "key_hash": _b64_encode(key_hash),
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        return meta

    def write_metadata_atomic(self, metadata: Dict[str, object], metadata_file: Optional[Path] = None) -> None:
        """Atomically write JSON metadata to the device (safe against partial writes)."""
        meta_path = self._meta_path(metadata_file)
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(metadata, indent=2)

        # Write to a temp file next to destination then replace
        dirpath = meta_path.parent
        with tempfile.NamedTemporaryFile("w", dir=dirpath, delete=False) as tf:
            tf.write(data)
            temp_name = tf.name
        os.replace(temp_name, str(meta_path))
        
        # Hide the file on Windows
        if sys.platform == "win32":
            if _hide_file_windows(meta_path):
                logger.debug("Successfully hid metadata file on Windows")
            else:
                logger.debug("Failed to hide metadata file on Windows (file still functional)")
        
        logger.info("Wrote metadata to %s", meta_path)

    def load_metadata(self, metadata_file: Optional[Path] = None) -> Dict[str, object]:
        meta_path = self._meta_path(metadata_file)
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata file not found: {meta_path}")
        with open(meta_path, "r") as f:
            data = json.load(f)
        # Basic validation
        required = {"salt", "key_hash", "iterations", "kdf"}
        if not required.issubset(set(data.keys())):
            raise ValueError("Metadata missing required fields")
        return data

    def verify_password(self, password: str, metadata: Dict[str, object]) -> bool:
        """Verify provided password against metadata (dict)."""
        # Ensure salt is bytes
        salt_raw = metadata["salt"]
        if isinstance(salt_raw, str):
            salt = _b64_decode(salt_raw)
        elif isinstance(salt_raw, bytes):
            salt = salt_raw
        else:
            raise TypeError(f"Salt must be str or bytes, got {type(salt_raw)}")
        
        # Ensure stored_key_hash is bytes
        key_hash_raw = metadata["key_hash"]
        if isinstance(key_hash_raw, str):
            stored_key_hash = _b64_decode(key_hash_raw)
        elif isinstance(key_hash_raw, bytes):
            stored_key_hash = key_hash_raw
        else:
            raise TypeError(f"Key hash must be str or bytes, got {type(key_hash_raw)}")
        
        iterations_raw = metadata.get("iterations", self.iterations)
        if isinstance(iterations_raw, (int, str)):
            iterations = int(iterations_raw)
        else:
            iterations = self.iterations

        derived_key = self.derive_key_from_password(password, salt, iterations=iterations)
        derived_key_hash = hashlib.sha256(derived_key).digest()

        result = secrets.compare_digest(derived_key_hash, stored_key_hash)
        logger.debug("Password verification result: %s", result)
        return result

    def get_encryption_key(self, password: str, metadata: Dict[str, object]) -> bytes:
        # Ensure salt is bytes
        salt_raw = metadata["salt"]
        if isinstance(salt_raw, str):
            salt = _b64_decode(salt_raw)
        elif isinstance(salt_raw, bytes):
            salt = salt_raw
        else:
            raise TypeError(f"Salt must be str or bytes, got {type(salt_raw)}")
        
        iterations_raw = metadata.get("iterations", self.iterations)
        if isinstance(iterations_raw, (int, str)):
            iterations = int(iterations_raw)
        else:
            iterations = self.iterations
        return self.derive_key_from_password(password, salt, iterations=iterations)

    def create_and_store_metadata(self, password: str, metadata_file: Optional[Path] = None) -> None:
        meta = self.create_auth_data(password)
        self.write_metadata_atomic(meta, metadata_file)

    def change_password(self, old_password: str, new_password: str, metadata_file: Optional[Path] = None) -> bool:
        """Verify old password and atomically replace metadata with new password data.

        Returns True if changed, False if verification failed.
        """
        try:
            meta = self.load_metadata(metadata_file)
        except FileNotFoundError:
            logger.error("No metadata to change password for")
            return False

        if not self.verify_password(old_password, meta):
            logger.warning("Old password verification failed")
            return False

        new_meta = self.create_auth_data(new_password)
        self.write_metadata_atomic(new_meta, metadata_file)
        logger.info("Password changed successfully")
        return True

    def cleanup_encrypted_files(self) -> int:
        """Clean up any encrypted files (.enc) in the device path.
        
        This should be called when overwriting metadata to prevent orphaned
        encrypted files that can't be decrypted with the new configuration.
        
        Returns:
            Number of encrypted files removed
        """
        removed_count = 0
        try:
            for enc_file in self.device_path.rglob("*.enc"):
                if enc_file.is_file():
                    # Skip system files and hidden directories
                    path_str = str(enc_file)
                    if any(part.startswith('.') for part in enc_file.parts[1:]):
                        continue
                    if any(sys_dir in path_str for sys_dir in ['System Volume Information', '$RECYCLE.BIN', '__MACOSX']):
                        continue
                    
                    try:
                        enc_file.unlink()
                        removed_count += 1
                        logger.debug(f"Removed encrypted file: {enc_file}")
                    except (OSError, IOError) as e:
                        logger.warning(f"Failed to remove encrypted file {enc_file}: {e}")
        except Exception as e:
            logger.error(f"Error during encrypted file cleanup: {e}")
        
        if removed_count > 0:
            logger.info(f"Cleaned up {removed_count} encrypted files")
        return removed_count

    def reinitialize_metadata(self, password: str, cleanup_encrypted_files: bool = True, metadata_file: Optional[Path] = None) -> bool:
        """Reinitialize metadata with a new password, optionally cleaning up encrypted files.
        
        This is a safe way to overwrite existing metadata, preventing orphaned encrypted files.
        
        Args:
            password: New password for the device
            cleanup_encrypted_files: Whether to remove existing encrypted files
            metadata_file: Optional custom metadata file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Remove existing metadata if it exists
            meta_path = self._meta_path(metadata_file)
            if meta_path.exists():
                meta_path.unlink()
                logger.info("Removed existing metadata file")
            
            # Clean up encrypted files if requested
            if cleanup_encrypted_files:
                removed_count = self.cleanup_encrypted_files()
                if removed_count > 0:
                    logger.info(f"Removed {removed_count} orphaned encrypted files")
            
            # Create and store new metadata
            self.create_and_store_metadata(password, metadata_file)
            logger.info("Successfully reinitialized metadata")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reinitialize metadata: {e}")
            return False


if __name__ == "__main__":
    # Demo / smoke test when run directly from src/ (so auth_manager.py and cli_auth.py are siblings)
    import sys

    dev = Path("./test_device")
    dev.mkdir(exist_ok=True)

    am = AuthManager(str(dev))
    try:
        # create metadata interactively only if run in a tty
        if sys.stdin.isatty():
            pw = am.prompt_for_password(confirm=True, visible=True)
        else:
            pw = "test123456"
        am.create_and_store_metadata(pw)
        loaded = am.load_metadata()
        ok = am.verify_password(pw, loaded)
        print("Verification OK:", ok)
    finally:
        # clean up demo metadata
        meta_path = dev / METADATA_FILENAME
        if meta_path.exists():
            meta_path.unlink()
        dev.rmdir()
