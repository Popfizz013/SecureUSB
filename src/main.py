#!/usr/bin/env python3
"""
SecureUSB - Main Entry Point

This is the main entry point for the SecureUSB application.
It provides both CLI and future GUI interfaces for secure USB operations.
"""

import argparse
import sys
from pathlib import Path

# Add the src directory to the Python path
src_dir = Path(__file__).parent
sys.path.insert(0, str(src_dir))

from ui.cli_interface import CLIInterface
from usb_detector import USBDetector
from crypto_engine import CryptoEngine
from auth_manager import AuthManager
from metadata import MetadataManager


def main():
    """Main entry point for SecureUSB application."""
    parser = argparse.ArgumentParser(
        description="SecureUSB - Secure USB Drive Protection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --detect              # Detect connected USB devices
  %(prog)s --encrypt /dev/sdb1   # Encrypt a USB device
  %(prog)s --decrypt /dev/sdb1   # Decrypt a USB device
        """
    )
    
    parser.add_argument(
        "--detect", 
        action="store_true",
        help="Detect and list connected USB devices"
    )
    
    parser.add_argument(
        "--encrypt",
        metavar="DEVICE",
        help="Encrypt the specified USB device"
    )
    
    parser.add_argument(
        "--decrypt",
        metavar="DEVICE", 
        help="Decrypt the specified USB device"
    )
    
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch GUI interface (future feature)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Initialize CLI interface
    cli = CLIInterface(verbose=args.verbose)
    
    try:
        if args.detect:
            cli.detect_usb_devices()
        elif args.encrypt:
            cli.encrypt_device(args.encrypt)
        elif args.decrypt:
            cli.decrypt_device(args.decrypt)
        elif args.gui:
            print("GUI interface is not implemented yet.")
            print("Please use CLI options for now.")
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()