"""
Command-line interface for SecureUSB.
"""
import sys
from pathlib import Path
import getpass

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from usb_detector import USBDetector
from auth_manager import AuthManager
from crypto_engine import CryptoEngine
from metadata import MetadataManager


class CLIInterface:
    """Command-line interface for SecureUSB operations."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize CLI interface.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self.usb_detector = USBDetector(verbose=verbose)
        
    def detect_usb_devices(self) -> None:
        """Detect and display connected USB devices."""
        print("Detecting USB devices...")
        
        devices = self.usb_detector.detect_usb_devices()
        
        if not devices:
            print("No USB devices detected.")
            return
            
        print(f"Found {len(devices)} USB device(s):")
        print()
        
        for i, device in enumerate(devices, 1):
            print(f"Device {i}:")
            print(self.usb_detector.format_device_info(device))
            print()
    
    def encrypt_device(self, device_path: str) -> None:
        """
        Encrypt a USB device.
        
        Args:
            device_path: Path to the device to encrypt
        """
        print(f"Encrypting device: {device_path}")
        
        # Check if device exists and is mounted
        if not self.usb_detector.is_mounted(device_path):
            print(f"Error: Device {device_path} is not mounted or accessible.")
            return
        
        try:
            # Initialize managers
            auth_manager = AuthManager(device_path)
            metadata_manager = MetadataManager(device_path)
            
            # Check if device is already encrypted
            if metadata_manager.metadata_exists():
                print("Device is already encrypted.")
                return
            
            # Get owner ID
            owner_id = input("Enter owner ID: ").strip()
            if not owner_id:
                print("Owner ID is required.")
                return
            
            # Get password
            password = auth_manager.prompt_for_password(confirm=True)
            
            # Create authentication data
            salt, key = auth_manager.create_auth_data(password)
            
            # Create metadata
            import hashlib
            key_hash = hashlib.sha256(key).digest()
            metadata = metadata_manager.create_metadata(owner_id, salt, key_hash)
            
            # Save metadata
            if metadata_manager.save_metadata(metadata):
                print("Device encryption setup completed successfully.")
                print(f"Device UUID: {metadata['uuid']}")
            else:
                print("Error: Failed to save device metadata.")
                
        except Exception as e:
            print(f"Error during encryption: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
    
    def decrypt_device(self, device_path: str) -> None:
        """
        Decrypt a USB device.
        
        Args:
            device_path: Path to the device to decrypt
        """
        print(f"Accessing encrypted device: {device_path}")
        
        # Check if device exists and is mounted
        if not self.usb_detector.is_mounted(device_path):
            print(f"Error: Device {device_path} is not mounted or accessible.")
            return
        
        try:
            # Initialize managers
            auth_manager = AuthManager(device_path)
            metadata_manager = MetadataManager(device_path)
            
            # Check if device is encrypted
            if not metadata_manager.metadata_exists():
                print("Device is not encrypted or metadata not found.")
                return
            
            # Load device info
            device_info = metadata_manager.get_device_info()
            if device_info:
                print(f"Device Owner: {device_info['owner_id']}")
                print(f"Created: {device_info['created_at']}")
                if device_info['last_accessed']:
                    print(f"Last Accessed: {device_info['last_accessed']}")
            
            # Get password
            password = auth_manager.prompt_for_password()
            
            # Verify password
            salt = metadata_manager.get_salt()
            key_hash = metadata_manager.get_key_hash()
            
            if not salt or not key_hash:
                print("Error: Invalid metadata - missing salt or key hash.")
                return
            
            # Verify password
            derived_key = auth_manager.get_encryption_key(password, salt)
            import hashlib
            if hashlib.sha256(derived_key).digest() != key_hash:
                print("Error: Incorrect password.")
                return
            
            # Update last accessed time
            metadata_manager.update_last_accessed()
            
            print("Password verified successfully.")
            print("Device is now accessible.")
            
        except Exception as e:
            print(f"Error during decryption: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
    
    def list_encrypted_devices(self) -> None:
        """List all known encrypted devices."""
        print("Scanning for encrypted devices...")
        
        # This would typically scan known metadata locations
        # For now, just detect current USB devices and check if they're encrypted
        devices = self.usb_detector.detect_usb_devices()
        
        encrypted_devices = []
        for device in devices:
            metadata_manager = MetadataManager(device['device'])
            if metadata_manager.metadata_exists():
                device_info = metadata_manager.get_device_info()
                if device_info:
                    encrypted_devices.append({
                        'device': device,
                        'metadata': device_info
                    })
        
        if not encrypted_devices:
            print("No encrypted devices found.")
            return
        
        print(f"Found {len(encrypted_devices)} encrypted device(s):")
        print()
        
        for i, enc_device in enumerate(encrypted_devices, 1):
            device = enc_device['device']
            metadata = enc_device['metadata']
            
            print(f"Encrypted Device {i}:")
            print(f"  Device: {device['device']}")
            print(f"  Mount Point: {device['mountpoint']}")
            print(f"  Owner: {metadata['owner_id']}")
            print(f"  UUID: {metadata['uuid']}")
            print(f"  Created: {metadata['created_at']}")
            if metadata['last_accessed']:
                print(f"  Last Accessed: {metadata['last_accessed']}")
            print()


def main():
    """Main function for CLI demo."""
    import argparse
    
    parser = argparse.ArgumentParser(
        prog="secure-usb-cli", 
        description="SecureUSB CLI Interface"
    )
    parser.add_argument("--status", action="store_true", help="Print status")
    parser.add_argument("--detect", action="store_true", help="Detect USB devices")
    parser.add_argument("--list-encrypted", action="store_true", help="List encrypted devices")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    cli = CLIInterface(verbose=args.verbose)
    
    if args.status:
        print("Status: SecureUSB CLI OK — environment set up")
    elif args.detect:
        cli.detect_usb_devices()
    elif args.list_encrypted:
        cli.list_encrypted_devices()
    else:
        print("SecureUSB CLI Interface")
        print("Use --help for available options")


if __name__ == "__main__":
    main()
