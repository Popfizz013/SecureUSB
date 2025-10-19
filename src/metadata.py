"""
Metadata management for SecureUSB.
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any
from pathlib import Path
import base64
import hashlib
import json
import os
import uuid as uuidlib
from datetime import datetime


@dataclass
class KDFParams:
    """Key derivation function parameters."""
    algo: str
    iters: int


@dataclass 
class DeviceMetadata:
    """Device metadata structure."""
    uuid: str
    owner_id: str
    salt_b64: str
    kdf: KDFParams
    created_at: str
    key_verifier_hex: str
    last_accessed: Optional[str] = None


class MetadataManager:
    """Manages device metadata for SecureUSB."""
    
    def __init__(self, device_path: str, metadata_dir: Optional[str] = None):
        """Initialize MetadataManager."""
        self.device_path = device_path
        self.metadata_dir = Path(metadata_dir) if metadata_dir else Path.home() / ".secureusb"
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        
    def get_metadata_file_path(self) -> Path:
        """Get the path to the metadata file for this device."""
        safe_name = self.device_path.replace('/', '_').replace('\\', '_').replace(':', '_')
        if safe_name.startswith('_'):
            safe_name = safe_name[1:]
        return self.metadata_dir / f"{safe_name}.secureusb"
    
    def create_metadata(self, owner_id: str, salt: bytes, key_hash: bytes) -> Dict[str, Any]:
        """Create new device metadata."""
        now = datetime.now().isoformat()
        
        metadata = {
            "uuid": str(uuidlib.uuid4()),
            "device_path": self.device_path,
            "owner_id": owner_id,
            "salt_b64": base64.b64encode(salt).decode("ascii"),
            "kdf": {
                "algo": "PBKDF2-HMAC-SHA256",
                "iters": 200000
            },
            "created_at": now,
            "last_accessed": now,
            "key_verifier_hex": key_hash.hex()
        }
        
        return metadata
    
    def save_metadata(self, metadata: Dict[str, Any]) -> bool:
        """Save metadata to file."""
        try:
            metadata_path = self.get_metadata_file_path()
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
            return True
        except (IOError, OSError):
            return False
    
    def load_metadata(self) -> Optional[Dict[str, Any]]:
        """Load metadata from file."""
        try:
            metadata_path = self.get_metadata_file_path()
            if not metadata_path.exists():
                return None
                
            with open(metadata_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (IOError, OSError, json.JSONDecodeError):
            return None
    
    def metadata_exists(self) -> bool:
        """Check if metadata file exists for this device."""
        return self.get_metadata_file_path().exists()
    
    def update_last_accessed(self) -> bool:
        """Update the last accessed timestamp in metadata."""
        metadata = self.load_metadata()
        if not metadata:
            return False
        
        metadata["last_accessed"] = datetime.now().isoformat()
        return self.save_metadata(metadata)
    
    def get_device_info(self) -> Optional[Dict[str, Any]]:
        """Get basic device information from metadata."""
        metadata = self.load_metadata()
        if not metadata:
            return None
        
        return {
            "uuid": metadata.get("uuid"),
            "owner_id": metadata.get("owner_id"),
            "created_at": metadata.get("created_at"),
            "last_accessed": metadata.get("last_accessed"),
            "device_path": metadata.get("device_path")
        }
    
    def get_salt(self) -> Optional[bytes]:
        """Get the salt from device metadata."""
        metadata = self.load_metadata()
        if not metadata:
            return None
        
        try:
            return base64.b64decode(metadata["salt_b64"])
        except (KeyError, ValueError):
            return None
    
    def get_key_hash(self) -> Optional[bytes]:
        """Get the key hash from device metadata."""
        metadata = self.load_metadata()
        if not metadata:
            return None
        
        try:
            return bytes.fromhex(metadata["key_verifier_hex"])
        except (KeyError, ValueError):
            return None
    
    def delete_metadata(self) -> bool:
        """Delete the metadata file (use with caution!)."""
        try:
            metadata_path = self.get_metadata_file_path()
            if metadata_path.exists():
                metadata_path.unlink()
                return True
            return False
        except (IOError, OSError):
            return False
    
    def backup_metadata(self, backup_suffix: Optional[str] = None) -> Optional[Path]:
        """Create a backup of the metadata file.
        
        Note: This method is kept for compatibility but consider using delete_metadata()
        instead if you're reinitializing to avoid cluttering the storage.
        """
        if not backup_suffix:
            from datetime import datetime
            backup_suffix = f"backup_{int(datetime.now().timestamp())}"
        
        try:
            metadata_path = self.get_metadata_file_path()
            if not metadata_path.exists():
                return None
            
            backup_path = metadata_path.with_suffix(f".{backup_suffix}")
            import shutil
            shutil.copy2(metadata_path, backup_path)
            return backup_path
        except (IOError, OSError):
            return None
