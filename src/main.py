#!/usr/bin/env python3
"""
SecureUSB - Main Entry Point

This is the main entry point for the SecureUSB application.
It provides both CLI and future GUI interfaces for secure USB operations.
"""

import argparse
import sys
import traceback
from ui.app import main as launch_gui
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
  %(prog)s --detect              # Detect connected USB devices once
  %(prog)s --monitor 2.0         # Monitor USB devices (poll every 2 seconds)  
  %(prog)s --status              # Show encryption status of all USB devices
  %(prog)s --encrypt "D:/"       # Encrypt all files on USB drive D:/
  %(prog)s --decrypt             # Auto-detect and decrypt encrypted USB device
        """
    )
    
    parser.add_argument(
        "--detect", 
        action="store_true",
        help="Detect and list connected USB devices"
    )
    
    parser.add_argument(
        "--monitor",
        type=float,
        metavar="INTERVAL",
        help="Monitor USB devices with polling interval in seconds (e.g., --monitor 2.0)"
    )
    
    parser.add_argument(
        "--encrypt",
        metavar="DEVICE",
        help="Encrypt the specified USB device"
    )
    
    parser.add_argument(
        "--decrypt",
        metavar="DEVICE", 
        nargs='?',
        const='auto',
        help="Decrypt the specified USB device (or auto-detect if no device specified)"
    )
    
    parser.add_argument(
        "--status",
        action="store_true", 
        help="Show encryption status of all detected USB devices"
    )
    
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch GUI interface"
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
        elif args.monitor:
            cli.monitor_usb_devices(args.monitor)
        elif args.encrypt:
            cli.encrypt_device(args.encrypt)
        elif args.decrypt:
            if args.decrypt == 'auto':
                cli.auto_decrypt_device()
            else:
                cli.decrypt_device(args.decrypt)
        elif args.status:
            cli.list_encrypted_devices()
        elif args.gui:
             launch_gui()  # Launch the Tkinter GUI
        else:
            # No CLI options supplied — launch the GUI by default for user convenience.
            # If you prefer CLI-only behavior, run the executable with the appropriate flags (e.g. --detect).
            launch_gui()
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        # Print a short error message to the console
        print(f"Error: {e}")

        # Write a full traceback to a log file on the user's Desktop to help debug GUI crashes
        try:
            desktop = Path.home() / 'OneDrive' / 'Desktop'
            # Fall back to standard Desktop location if OneDrive path doesn't exist
            if not desktop.exists():
                desktop = Path.home() / 'Desktop'
            log_path = desktop / 'secureusb-exception.log'
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write('\n---- Exception captured: ' + str(Path(__file__)) + ' ----\n')
                traceback.print_exc(file=f)
            print(f"A detailed traceback was written to: {log_path}")
        except Exception:
            # If writing the file fails, ensure we still show traceback when verbose
            if args.verbose:
                traceback.print_exc()

        if args.verbose:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()