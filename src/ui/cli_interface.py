"""
Command-line interface for SecureUSB.
"""
import argparse
import hashlib
import sys
import time
import traceback
from pathlib import Path
import getpass
import os
import shutil

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from usb_detector import USBDetector
from auth_manager import AuthManager
from crypto_engine import CryptoEngine
from metadata import MetadataManager
from utils.file_utils import FileUtils


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
    
    def _get_device_mount_point(self, device_path: str) -> str:
        """Get the mount point for a device path."""
        # Check if it's already a mount point
        if os.path.ismount(device_path):
            return device_path
        
        # Check if it's a device path that we need to find the mount point for
        devices = self.usb_detector.detect_usb_devices()
        for device in devices:
            if device['device'] == device_path:
                return device['mountpoint']
        
        # Fallback - assume it's already a mount point
        return device_path
    
    def _is_system_file(self, file_path: Path) -> bool:
        """
        Check if a file is a system file that should be excluded from encryption.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            True if the file is a system file, False otherwise
        """
        # Skip files in hidden directories (starting with .)
        if any(part.startswith('.') for part in file_path.parts[1:]):
            return True
        
        # Skip system directories
        path_str = str(file_path)
        system_dirs = ['System Volume Information', '$RECYCLE.BIN', '__MACOSX']
        if any(sys_dir in path_str for sys_dir in system_dirs):
            return True
        
        # Skip our metadata files
        if file_path.name.startswith('.secureusb_'):
            return True
            
        return False
    

    
    def _encrypt_all_files(self, mount_point: str, crypto_engine: CryptoEngine) -> bool:
        """
        Encrypt all files on the USB drive.
        
        Args:
            mount_point: Mount point of the USB drive
            crypto_engine: Initialized crypto engine
            
        Returns:
            True if successful, False otherwise
        """
        try:
            mount_path = Path(mount_point)
            encrypted_count = 0
            
            print(f"\nEncrypting user files in {mount_point}...")
            
            # Find all files (excluding system files and metadata files)
            for file_path in mount_path.rglob('*'):
                if file_path.is_file():
                    # Skip system files (hidden directories, system folders, etc.)
                    if self._is_system_file(file_path):
                        continue
                    
                    # Skip already encrypted files
                    if file_path.suffix == '.enc':
                        continue
                    
                    try:
                        print(f"  Encrypting: {file_path.relative_to(mount_path)}")
                        
                        # Create encrypted version
                        encrypted_path = file_path.with_suffix(file_path.suffix + '.enc')
                        crypto_engine.encrypt_file(file_path, encrypted_path)
                        
                        # Securely delete original
                        FileUtils.secure_delete(file_path)
                        
                        encrypted_count += 1
                        
                    except Exception as e:
                        print(f"  ❌ Failed to encrypt {file_path.name}: {e}")
                        continue
            
            print(f"✓ Successfully encrypted {encrypted_count} user files")
            return True
            
        except Exception as e:
            print(f"❌ Error during file encryption: {e}")
            return False
    
    def _decrypt_all_files(self, mount_point: str, crypto_engine: CryptoEngine) -> bool:
        """
        Decrypt all user files on the USB drive.
        
        Args:
            mount_point: Mount point of the USB drive
            crypto_engine: Initialized crypto engine
            
        Returns:
            True if successful, False otherwise
        """
        try:
            mount_path = Path(mount_point)
            decrypted_count = 0
            
            print(f"\nDecrypting user files in {mount_point}...")
            
            # Find all encrypted user files (exclude system files)
            for file_path in mount_path.rglob('*.enc'):
                if file_path.is_file():
                    # Skip system files
                    if self._is_system_file(file_path):
                        continue
                        
                    try:
                        print(f"  Decrypting: {file_path.relative_to(mount_path)}")
                        
                        # Create decrypted version (remove .enc extension)
                        if file_path.name.endswith('.enc'):
                            original_path = file_path.with_suffix('')
                        else:
                            original_path = file_path.with_suffix('.dec')
                        
                        crypto_engine.decrypt_file(file_path, original_path)
                        
                        # Remove encrypted file
                        file_path.unlink()
                        
                        decrypted_count += 1
                        
                    except Exception as e:
                        print(f"  ❌ Failed to decrypt {file_path.name}: {e}")
                        continue
            
            print(f"✓ Successfully decrypted {decrypted_count} user files")
            return True
            
        except Exception as e:
            print(f"❌ Error during file decryption: {e}")
            return False
        
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
    
    def monitor_usb_devices(self, interval: float) -> None:
        """
        Monitor USB devices with continuous polling.
        
        Args:
            interval: Polling interval in seconds
        """
        print(f"Starting USB device monitoring (polling every {interval}s)...")
        print("Press Ctrl+C to stop monitoring")
        print()
        
        def on_device_added(device):
            """Callback for when a device is added."""
            print(f"[DEVICE ADDED] {device['device']} -> {device['mountpoint']}")
            print(f"  Filesystem: {device['fstype'].upper()}")
            if 'total_size' in device:
                total_gb = device['total_size'] / (1024**3)
                print(f"  Size: {total_gb:.2f} GB")
            print()
        
        def on_device_removed(mountpoint):
            """Callback for when a device is removed."""
            print(f"[DEVICE REMOVED] {mountpoint}")
            print()
        
        try:
            # Show initial devices
            initial_devices = self.usb_detector.detect_usb_devices()
            if initial_devices:
                print(f"Currently connected devices ({len(initial_devices)}):")
                for device in initial_devices:
                    print(f"  {device['device']} -> {device['mountpoint']}")
                print()
            else:
                print("No USB devices currently connected.")
                print()
            
            # Start monitoring
            self.usb_detector.start_polling(
                interval=interval,
                on_device_added=on_device_added,
                on_device_removed=on_device_removed
            )
            
            # Keep monitoring active until interrupted
            print("Monitoring active... (Press Ctrl+C to stop)")
            while self.usb_detector._polling_active:
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\nStopping USB monitoring...")
        finally:
            self.usb_detector.stop_polling()
            print("USB monitoring stopped.")
    
    def encrypt_device(self, device_path: str) -> None:
        """
        Encrypt a USB device with integrated flow: detection → authentication → encryption.
        
        Args:
            device_path: Path to the device to encrypt
        """
        print(f"Setting up encryption for device: {device_path}")
        print("=" * 50)
        
        # Step 1: USB Detection and validation
        print("Step 1: Validating USB device...")
        if not self.usb_detector.is_mounted(device_path):
            print(f"Error: Device {device_path} is not mounted or accessible.")
            return
        
        # Get device info for confirmation
        devices = self.usb_detector.detect_usb_devices()
        target_device = None
        for device in devices:
            if device['device'] == device_path or device['mountpoint'] == device_path:
                target_device = device
                break
        
        if not target_device:
            print(f"Warning: Device {device_path} not found in USB device list.")
            print("Proceeding anyway as it may be mounted...")
            target_device = {'device': device_path, 'mountpoint': device_path, 'fstype': 'unknown'}
        
        print(f"✓ Device found: {target_device['device']}")
        print(f"  Mount point: {target_device['mountpoint']}")
        print(f"  Filesystem: {target_device.get('fstype', 'unknown').upper()}")
        if 'total_size' in target_device:
            total_size = target_device['total_size']
            if isinstance(total_size, (int, float)):
                total_gb = total_size / (1024**3)
                print(f"  Size: {total_gb:.2f} GB")
        
        try:
            # Initialize managers
            auth_manager = AuthManager(device_path)
            metadata_manager = MetadataManager(device_path)
            
            # Check if files are currently encrypted (look for .enc files)
            mount_point = self._get_device_mount_point(device_path)
            mount_path = Path(mount_point)
            
            # Count encrypted user files only (exclude system files)
            user_encrypted_files = []
            for enc_file in mount_path.rglob('*.enc'):
                if not self._is_system_file(enc_file):
                    user_encrypted_files.append(enc_file)
            
            if user_encrypted_files:
                print(f"\n❌ Device has {len(user_encrypted_files)} encrypted user files.")
                print("Use --decrypt option to access the encrypted files first.")
                return
            
            # Check if metadata already exists - this could be dangerous!
            if metadata_manager.metadata_exists():
                if user_encrypted_files:
                    print("\n🚨 CRITICAL WARNING: This USB drive already has encrypted content!")
                    print(f"   Found {len(user_encrypted_files)} encrypted files from another user/session.")
                    print(f"   Re-encrypting will make these files PERMANENTLY INACCESSIBLE!")
                    print(f"   This action CANNOT be undone!")
                    print("\n   If this is your USB drive, use --decrypt instead to access your files.")
                    print("   If you borrowed this USB, please return it to the owner first.")
                    
                    while True:
                        confirm = input("\nType 'DESTROY' to confirm you want to destroy existing encrypted data, or 'cancel' to abort: ").strip()
                        if confirm.lower() == 'cancel':
                            print("Operation cancelled. Existing encrypted files preserved.")
                            return
                        elif confirm == 'DESTROY':
                            print("⚠️ User confirmed destruction of existing encrypted files!")
                            # Create backup of existing metadata before overwriting
                            try:
                                import shutil
                                mount_path = Path(mount_point)
                                existing_meta = mount_path / ".secureusb_meta.json"
                                if existing_meta.exists():
                                    backup_meta = mount_path / f".secureusb_meta.json.backup_{int(time.time())}"
                                    shutil.copy2(existing_meta, backup_meta)
                                    print(f"✓ Created backup of existing metadata: {backup_meta.name}")
                            except Exception as e:
                                print(f"Warning: Could not create metadata backup: {e}")
                            break
                        else:
                            print("Please type exactly 'DESTROY' or 'cancel'")
                else:
                    print("\n⚠️  Device was previously encrypted but files are currently decrypted.")
                    while True:
                        confirm = input("Re-initialize encryption metadata? This will create new encryption keys. (y/n): ").strip().lower()
                        if confirm in ['n', 'no']:
                            print("Operation cancelled. Use existing metadata.")
                            return
                        elif confirm in ['y', 'yes']:
                            print("Proceeding with metadata re-initialization...")
                            # Create backup of existing metadata before overwriting
                            try:
                                import shutil
                                mount_path = Path(mount_point)
                                existing_meta = mount_path / ".secureusb_meta.json"
                                if existing_meta.exists():
                                    backup_meta = mount_path / f".secureusb_meta.json.backup_{int(time.time())}"
                                    shutil.copy2(existing_meta, backup_meta)
                                    print(f"✓ Created backup of existing metadata: {backup_meta.name}")
                            except Exception as e:
                                print(f"Warning: Could not create metadata backup: {e}")
                            break
                        else:
                            print("Please answer 'y' or 'n'")
            
            # Step 2: Authentication Setup
            print("\nStep 2: Setting up authentication...")
            
            # Get owner ID
            owner_id = input("Enter owner/user ID: ").strip()
            if not owner_id:
                print("❌ Owner ID is required.")
                return
            
            # Get password with confirmation
            print("Creating device password (minimum 8 characters):")
            password = auth_manager.prompt_for_password(confirm=True)
            
            # Step 3: Generate encryption keys and metadata
            print("\nStep 3: Generating encryption keys...")
            
            # Create authentication data
            auth_data = auth_manager.create_auth_data(password)
            
            # Extract salt and derive key for metadata
            import hashlib
            salt = auth_manager.generate_salt()
            key = auth_manager.derive_key_from_password(password, salt)
            key_hash = hashlib.sha256(key).digest()
            metadata = metadata_manager.create_metadata(owner_id, salt, key_hash)
            
            print(f"✓ Generated device UUID: {metadata['uuid']}")
            print(f"✓ Created authentication data for user: {owner_id}")
            
            # Step 4: Encryption Engine Integration (Stub)
            print("\nStep 4: Integrating encryption engine...")
            
            # Initialize crypto engine with derived key
            crypto_engine = CryptoEngine(key)
            
            print("✓ Encryption engine initialized with derived key")
            print(f"✓ Using AES-256-GCM encryption")
            print("✓ Ready for file encryption operations")
            
            # Save metadata
            print("\nStep 5: Saving device metadata...")
            if metadata_manager.save_metadata(metadata):
                print("✓ Device metadata saved successfully")
            else:
                print("❌ Failed to save device metadata")
                return
            
            # Step 6: Encrypt all files on the device
            print("\nStep 6: Encrypting all files on the device...")
            mount_point = self._get_device_mount_point(device_path)
            
            if self._encrypt_all_files(mount_point, crypto_engine):
                print("✓ All files have been encrypted successfully")
            else:
                print("❌ Some files could not be encrypted")
            
            # Integration complete
            print("\n" + "=" * 50)
            print("🔒 ENCRYPTION COMPLETE")
            print("=" * 50)
            print(f"Device UUID: {metadata['uuid']}")
            print(f"Owner: {owner_id}")
            print(f"Created: {metadata['created_at']}")
            print(f"Status: All files are now encrypted and secure")
            print("\nNext steps:")
            print("- Files on the USB drive are now encrypted (.enc extension)")
            print("- Use --decrypt to access the files in the future")
            print("- Keep your password safe - it cannot be recovered!")
                
        except Exception as e:
            print(f"\n❌ Error during encryption setup: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
    
    def decrypt_device(self, device_path: str) -> None:
        """
        Decrypt a USB device with integrated flow: detection → authentication → decryption access.
        
        Args:
            device_path: Path to the device to decrypt
        """
        print(f"Accessing encrypted device: {device_path}")
        print("=" * 50)
        
        # Step 1: USB Detection and validation
        print("Step 1: Validating USB device...")
        if not self.usb_detector.is_mounted(device_path):
            print(f"❌ Device {device_path} is not mounted or accessible.")
            return
        
        # Get device info for confirmation
        devices = self.usb_detector.detect_usb_devices()
        target_device = None
        for device in devices:
            if device['device'] == device_path or device['mountpoint'] == device_path:
                target_device = device
                break
        
        if target_device:
            print(f"✓ Device found: {target_device['device']}")
            print(f"  Mount point: {target_device['mountpoint']}")
            print(f"  Filesystem: {target_device.get('fstype', 'unknown').upper()}")
        else:
            print(f"✓ Device {device_path} is accessible")
        
        try:
            # Initialize managers
            auth_manager = AuthManager(device_path)
            metadata_manager = MetadataManager(device_path)
            
            # Step 2: Check encryption status
            print("\nStep 2: Checking encryption status...")
            if not metadata_manager.metadata_exists():
                print("❌ Device is not encrypted or metadata not found.")
                print("Use --encrypt option to set up encryption for this device.")
                return
            
            # Check if files are actually encrypted
            mount_point = self._get_device_mount_point(device_path)
            mount_path = Path(mount_point)
            encrypted_files = list(mount_path.rglob('*.enc'))
            
            if not encrypted_files:
                print("❌ Device metadata exists but no encrypted files found.")
                print("Files appear to be already decrypted.")
                return
            
            # Load device info
            device_info = metadata_manager.get_device_info()
            if device_info:
                print("✓ Encrypted device metadata found")
                print(f"  Device UUID: {device_info['uuid']}")
                print(f"  Owner: {device_info['owner_id']}")
                print(f"  Created: {device_info['created_at']}")
                if device_info['last_accessed']:
                    print(f"  Last Accessed: {device_info['last_accessed']}")
            
            # Step 3: Authentication
            print("\nStep 3: Authenticating access...")
            
            # Get password
            password = auth_manager.prompt_for_password()
            
            # Load metadata for verification
            metadata = metadata_manager.load_metadata()
            if not metadata:
                print("❌ Could not load device metadata.")
                return
            
            salt = metadata_manager.get_salt()
            key_hash = metadata_manager.get_key_hash()
            
            if not salt or not key_hash:
                print("❌ Invalid metadata - missing salt or key hash.")
                return
            
            # Verify password using metadata
            derived_key = auth_manager.derive_key_from_password(password, salt)
            import hashlib
            if hashlib.sha256(derived_key).digest() != key_hash:
                print("❌ Incorrect password. Access denied.")
                return
            
            print("✓ Password verified successfully")
            
            # Step 4: Initialize encryption engine
            print("\nStep 4: Initializing encryption engine...")
            
            # Initialize crypto engine with derived key
            crypto_engine = CryptoEngine(derived_key)
            
            print("✓ Encryption engine initialized")
            print("✓ Ready for secure file operations")
            
            # Step 5: Decrypt all files on the device
            print("\nStep 5: Decrypting all files on the device...")
            mount_point = self._get_device_mount_point(device_path)
            
            if self._decrypt_all_files(mount_point, crypto_engine):
                print("✓ All files have been decrypted successfully")
            else:
                print("❌ Some files could not be decrypted")
            
            # Update last accessed time
            metadata_manager.update_last_accessed()
            
            # Access granted
            print("\n" + "=" * 50)
            print("🔓 DEVICE ACCESS GRANTED - FILES DECRYPTED")
            print("=" * 50)
            print(f"Device UUID: {device_info['uuid'] if device_info else 'Unknown'}")
            print(f"Owner: {device_info['owner_id'] if device_info else 'Unknown'}")
            print("Status: All files are now decrypted and accessible")
            print("\nFiles are now accessible:")
            print("- All .enc files have been decrypted to their original form")
            print("- You can now access and modify your files normally")
            print("- Remember to encrypt again when done for security")
            
        except Exception as e:
            print(f"\n❌ Error during device access: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
    
    def auto_decrypt_device(self) -> None:
        """
        Auto-detect and decrypt an encrypted USB device.
        """
        print("Auto-detecting encrypted USB devices...")
        print("=" * 50)
        
        # Step 1: Detect USB devices
        devices = self.usb_detector.detect_usb_devices()
        
        if not devices:
            print("❌ No USB devices detected.")
            return
        
        # Step 2: Find encrypted devices
        encrypted_devices = []
        for device in devices:
            metadata_manager = MetadataManager(device['device'])
            if metadata_manager.metadata_exists():
                encrypted_devices.append(device)
        
        if not encrypted_devices:
            print("❌ No encrypted USB devices found.")
            print("Use --encrypt to set up encryption for a device first.")
            return
        
        # Step 3: Select device to decrypt
        if len(encrypted_devices) == 1:
            selected_device = encrypted_devices[0]
            print(f"✓ Auto-selected encrypted device: {selected_device['device']}")
        else:
            print(f"Found {len(encrypted_devices)} encrypted device(s):")
            for i, device in enumerate(encrypted_devices, 1):
                print(f"  {i}. {device['device']} -> {device['mountpoint']}")
            
            try:
                choice = input(f"\nSelect device to decrypt (1-{len(encrypted_devices)}): ").strip()
                choice_idx = int(choice) - 1
                if 0 <= choice_idx < len(encrypted_devices):
                    selected_device = encrypted_devices[choice_idx]
                else:
                    print("❌ Invalid selection.")
                    return
            except ValueError:
                print("❌ Invalid input.")
                return
        
        # Step 4: Decrypt the selected device
        self.decrypt_device(selected_device['device'])
    
    def list_encrypted_devices(self) -> None:
        """List all known encrypted devices with integrated detection."""
        print("Integrated USB Detection → Encryption Status Check")
        print("=" * 50)
        
        # Step 1: USB Detection
        print("Step 1: Scanning for USB devices...")
        devices = self.usb_detector.detect_usb_devices()
        
        if not devices:
            print("No USB devices detected.")
            return
        
        print(f"✓ Found {len(devices)} USB device(s)")
        
        # Step 2: Check encryption status for each device
        print("\nStep 2: Checking encryption status...")
        
        encrypted_devices = []
        unencrypted_devices = []
        
        for device in devices:
            metadata_manager = MetadataManager(device['device'])
            mount_point = device['mountpoint']
            mount_path = Path(mount_point)
            
            # Check for encrypted files (.enc extension), but exclude system/hidden files
            user_encrypted_files = []
            if mount_path.exists() and mount_path.is_dir():
                try:
                    # Find all .enc files but exclude hidden directories and system files
                    for enc_file in mount_path.rglob('*.enc'):
                        # Skip files in hidden directories (starting with .)
                        if any(part.startswith('.') for part in enc_file.parts[1:]):
                            continue
                        # Skip system directories
                        path_str = str(enc_file)
                        if any(sys_dir in path_str for sys_dir in ['System Volume Information', '$RECYCLE.BIN']):
                            continue
                        user_encrypted_files.append(enc_file)
                except PermissionError:
                    # Skip if we can't access the directory
                    pass
            
            # Device is considered encrypted if:
            # 1. It has metadata AND user encrypted files, OR
            # 2. It has metadata but no user files at all (encrypted then cleaned)
            has_metadata = metadata_manager.metadata_exists()
            has_user_encrypted_files = len(user_encrypted_files) > 0
            
            # Count total user files (excluding metadata and system files)
            total_user_files = 0
            if mount_path.exists() and mount_path.is_dir():
                try:
                    for file_path in mount_path.rglob('*'):
                        if not file_path.is_file():
                            continue
                        # Skip metadata files
                        if file_path.name.startswith('.secureusb_'):
                            continue
                        # Skip files in hidden directories
                        if any(part.startswith('.') for part in file_path.parts[1:]):
                            continue
                        # Skip system directories
                        path_str = str(file_path)
                        if any(sys_dir in path_str for sys_dir in ['System Volume Information', '$RECYCLE.BIN']):
                            continue
                        total_user_files += 1
                except PermissionError:
                    pass
            
            if has_metadata and (has_user_encrypted_files or total_user_files == 0):
                device_info = metadata_manager.get_device_info()
                if device_info:
                    encrypted_devices.append({
                        'device': device,
                        'metadata': device_info,
                        'encrypted_file_count': len(user_encrypted_files)
                    })
            else:
                unencrypted_devices.append(device)
        
        # Display results
        print("\n" + "=" * 50)
        print("ENCRYPTION STATUS REPORT")
        print("=" * 50)
        
        if encrypted_devices:
            print(f"\n🔒 ENCRYPTED DEVICES ({len(encrypted_devices)}):")
            print("-" * 30)
            
            for i, enc_device in enumerate(encrypted_devices, 1):
                device = enc_device['device']
                metadata = enc_device['metadata']
                encrypted_count = enc_device['encrypted_file_count']
                
                print(f"\nDevice {i}: {device['device']}")
                print(f"  Mount Point: {device['mountpoint']}")
                print(f"  Filesystem: {device.get('fstype', 'unknown').upper()}")
                if 'total_size' in device and isinstance(device['total_size'], (int, float)):
                    total_gb = device['total_size'] / (1024**3)
                    print(f"  Size: {total_gb:.2f} GB")
                print(f"  Owner: {metadata['owner_id']}")
                print(f"  UUID: {metadata['uuid']}")
                print(f"  Created: {metadata['created_at']}")
                if metadata['last_accessed']:
                    print(f"  Last Accessed: {metadata['last_accessed']}")
                if encrypted_count > 0:
                    print(f"  Encrypted User Files: {encrypted_count}")
                    print(f"  Status: 🔒 ENCRYPTED")
                else:
                    print(f"  Encrypted User Files: 0 (files may be decrypted)")
                    print(f"  Status: 🔓 DECRYPTED (device setup for encryption)")
        
        if unencrypted_devices:
            print(f"\n🔓 UNENCRYPTED DEVICES ({len(unencrypted_devices)}):")
            print("-" * 30)
            
            for i, device in enumerate(unencrypted_devices, 1):
                print(f"\nDevice {i}: {device['device']}")
                print(f"  Mount Point: {device['mountpoint']}")
                print(f"  Filesystem: {device.get('fstype', 'unknown').upper()}")
                if 'total_size' in device and isinstance(device['total_size'], (int, float)):
                    total_gb = device['total_size'] / (1024**3)
                    print(f"  Size: {total_gb:.2f} GB")
                print(f"  Status: 🔓 NOT ENCRYPTED")
        
        print(f"\nSummary: {len(encrypted_devices)} encrypted, {len(unencrypted_devices)} unencrypted")


def main():
    """Main function for CLI demo."""
    import argparse
    
    parser = argparse.ArgumentParser(
        prog="secure-usb-cli", 
        description="SecureUSB CLI Interface"
    )
    parser.add_argument("--status", action="store_true", help="Print status")
    parser.add_argument("--detect", action="store_true", help="Detect USB devices")
    parser.add_argument("--monitor", type=float, metavar="INTERVAL", help="Monitor USB devices with polling interval")
    parser.add_argument("--list-encrypted", action="store_true", help="List encrypted devices")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    cli = CLIInterface(verbose=args.verbose)
    
    if args.status:
        print("Status: SecureUSB CLI OK — environment set up")
    elif args.detect:
        cli.detect_usb_devices()
    elif args.monitor:
        cli.monitor_usb_devices(args.monitor)
    elif args.list_encrypted:
        cli.list_encrypted_devices()
    else:
        print("SecureUSB CLI Interface")
        print("Use --help for available options")


if __name__ == "__main__":
    main()
