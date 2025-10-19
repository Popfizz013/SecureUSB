"""
USB Device Detection for SecureUSB.

Cross-platform USB detection using psutil with polling capabilities.
Supports Windows, macOS, and Linux with appropriate platform-specific filters.
"""
import argparse
import json
import os
import platform
import subprocess
import time
import threading
from typing import List, Dict, Optional, Callable, Set
from pathlib import Path

import psutil

# Filesystem types commonly used on removable storage
LIKELY_REMOVABLE_FS = {"vfat", "exfat", "fat", "fat32", "msdos", "ntfs", "hfs", "apfs", "ext2", "ext3", "ext4"}

# macOS specific settings
MAC_USER_VOLUME_PREFIX = "/Volumes/"
MAC_EXCLUDE_BASENAMES = {"Recovery", "Macintosh HD", "Preboot", "Update", "Data"}

# Windows specific settings  
WIN_EXCLUDE_DRIVES = {"C:"}  # System drives to exclude (removed D: as it's commonly used for USB)


class USBDetector:
    """Cross-platform USB device detector with polling capabilities."""
    
    def __init__(self, verbose: bool = False):
        """
        Initialize USB detector.
        
        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.platform = platform.system()
        self._polling_thread = None
        self._polling_active = False
        self._poll_interval = 2.0
        self._device_callbacks = []
        self._last_devices = set()
        
    def log(self, message: str) -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(f"[USBDetector] {message}")
    
    def _darwin_user_visible(self, partition) -> bool:
        """Check if a macOS partition is user-visible and likely removable."""
        mountpoint = partition.mountpoint
        if not mountpoint.startswith(MAC_USER_VOLUME_PREFIX):
            return False
        
        base = os.path.basename(mountpoint.rstrip("/"))
        if base in MAC_EXCLUDE_BASENAMES:
            return False
            
        return True
    
    def _windows_is_removable(self, partition) -> bool:
        """Check if a Windows partition is likely removable."""
        device = partition.device
        mountpoint = partition.mountpoint
        fstype = (partition.fstype or "").lower()
        
        # Exclude common system drives (only C: by default)
        if device.rstrip("\\") in WIN_EXCLUDE_DRIVES:
            return False
            
        # Check if drive letter is a system drive
        if mountpoint and len(mountpoint) >= 2:
            drive_letter = mountpoint[:2]
            if drive_letter in WIN_EXCLUDE_DRIVES:
                return False
        
        # Additional heuristics for removable drives:
        # 1. FAT filesystems are more likely to be removable
        if fstype in {"fat", "fat32", "exfat", "vfat"}:
            return True
            
        # 2. NTFS drives could be external HDDs, but be more cautious
        # Check if it's not the system drive (C:)
        if fstype == "ntfs" and device.rstrip("\\") != "C:":
            return True
        
        return True
    
    def _diskutil_external_or_removable(self, device: str) -> bool:
        """Use macOS diskutil to verify if device is external/removable."""
        try:
            result = subprocess.run(
                ["/usr/sbin/diskutil", "info", device],
                capture_output=True, text=True, check=False, timeout=5
            )
            if result.returncode != 0:
                return False
                
            output = result.stdout or ""
            # Check for indicators of external/removable storage
            external_indicators = [
                "External:               Yes",
                "Device Location:        External", 
                "Removable Media:        Yes",
                "Removable Media:        Removable",
                "Protocol:               USB"
            ]
            return any(indicator in output for indicator in external_indicators)
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.log(f"diskutil check failed for {device}: {e}")
            return False
    
    def detect_usb_devices(self, verify_with_diskutil: bool = False) -> List[Dict]:
        """
        Detect currently connected USB devices.
        
        Args:
            verify_with_diskutil: On macOS, use diskutil for additional verification
            
        Returns:
            List of device information dictionaries
        """
        devices = []
        
        try:
            partitions = psutil.disk_partitions(all=False)
            self.log(f"Found {len(partitions)} partitions")
            
            for partition in partitions:
                fstype = (partition.fstype or "").lower()
                mountpoint = partition.mountpoint
                device = getattr(partition, "device", "")
                
                self.log(f"Checking partition: {device} -> {mountpoint} ({fstype})")
                
                # Skip partitions without filesystem or with virtual filesystems
                if not fstype or fstype in {"nullfs", "devfs", "sysfs", "proc"}:
                    continue
                
                # Filter by filesystem type
                if fstype not in LIKELY_REMOVABLE_FS:
                    self.log(f"Skipping {device}: filesystem {fstype} not in removable list")
                    continue
                
                # Platform-specific filtering
                if self.platform == "Darwin":
                    if not self._darwin_user_visible(partition):
                        self.log(f"Skipping {device}: not user-visible on macOS")
                        continue
                        
                    if verify_with_diskutil and device:
                        if not self._diskutil_external_or_removable(device):
                            self.log(f"Skipping {device}: diskutil indicates not external/removable")
                            continue
                            
                elif self.platform == "Windows":
                    if not self._windows_is_removable(partition):
                        self.log(f"Skipping {device}: likely system drive on Windows")
                        continue
                
                # Try to get additional device information
                device_info = {
                    "device": device,
                    "mountpoint": mountpoint,
                    "fstype": fstype,
                }
                
                # Get disk usage if possible
                try:
                    usage = psutil.disk_usage(mountpoint)
                    device_info.update({
                        "total_size": usage.total,
                        "used": usage.used, 
                        "free": usage.free,
                        "percent_used": (usage.used / usage.total * 100) if usage.total > 0 else 0
                    })
                except (PermissionError, FileNotFoundError, OSError) as e:
                    self.log(f"Could not get disk usage for {mountpoint}: {e}")
                
                devices.append(device_info)
                self.log(f"Added device: {device_info}")
                
        except Exception as e:
            self.log(f"Error during device detection: {e}")
            
        return devices
    
    def is_mounted(self, device_path: str) -> bool:
        """
        Check if a device is currently mounted.
        
        Args:
            device_path: Path to the device or mount point
            
        Returns:
            True if device is mounted, False otherwise
        """
        try:
            # Check if it's a mount point
            if os.path.isdir(device_path):
                return os.path.ismount(device_path)
            
            # Check if device is in mounted partitions
            partitions = psutil.disk_partitions()
            for partition in partitions:
                if partition.device == device_path or partition.mountpoint == device_path:
                    return True
                    
            return False
            
        except Exception as e:
            self.log(f"Error checking if {device_path} is mounted: {e}")
            return False
    
    def format_device_info(self, device: Dict) -> str:
        """
        Format device information for display.
        
        Args:
            device: Device information dictionary
            
        Returns:
            Formatted string representation
        """
        lines = [
            f"  Device: {device['device']}",
            f"  Mount Point: {device['mountpoint']}",
            f"  Filesystem: {device['fstype'].upper()}"
        ]
        
        if 'total_size' in device:
            total_gb = device['total_size'] / (1024**3)
            used_gb = device['used'] / (1024**3)
            free_gb = device['free'] / (1024**3)
            
            lines.extend([
                f"  Total Size: {total_gb:.2f} GB",
                f"  Used: {used_gb:.2f} GB ({device['percent_used']:.1f}%)",
                f"  Free: {free_gb:.2f} GB"
            ])
        
        return '\n'.join(lines)
    
    def start_polling(self, interval: float = 2.0, 
                     on_device_added: Optional[Callable[[Dict], None]] = None,
                     on_device_removed: Optional[Callable[[str], None]] = None) -> None:
        """
        Start polling for USB device changes.
        
        Args:
            interval: Polling interval in seconds
            on_device_added: Callback for when a device is added
            on_device_removed: Callback for when a device is removed
        """
        if self._polling_active:
            self.log("Polling already active")
            return
        
        self._poll_interval = interval
        self._polling_active = True
        
        # Store callbacks
        if on_device_added:
            self.add_device_callback('added', on_device_added)
        if on_device_removed:
            self.add_device_callback('removed', on_device_removed)
        
        # Initialize with current devices
        current_devices = self.detect_usb_devices()
        self._last_devices = {dev['mountpoint'] for dev in current_devices}
        
        self._polling_thread = threading.Thread(target=self._polling_loop, daemon=True)
        self._polling_thread.start()
        
        self.log(f"Started polling with {interval}s interval")
    
    def stop_polling(self) -> None:
        """Stop the polling loop."""
        if not self._polling_active:
            return
            
        self._polling_active = False
        if self._polling_thread:
            self._polling_thread.join(timeout=5.0)
            
        self.log("Stopped polling")
    
    def add_device_callback(self, event_type: str, callback: Callable) -> None:
        """
        Add a callback for device events.
        
        Args:
            event_type: 'added' or 'removed'
            callback: Function to call when event occurs
        """
        self._device_callbacks.append((event_type, callback))
    
    def _polling_loop(self) -> None:
        """Internal polling loop that runs in a separate thread."""
        while self._polling_active:
            try:
                current_devices = self.detect_usb_devices()
                current_mountpoints = {dev['mountpoint'] for dev in current_devices}
                
                # Check for added devices
                added_mountpoints = current_mountpoints - self._last_devices
                for mountpoint in added_mountpoints:
                    device = next((dev for dev in current_devices if dev['mountpoint'] == mountpoint), None)
                    if device:
                        self.log(f"Device added: {device['device']} at {mountpoint}")
                        self._trigger_callbacks('added', device)
                
                # Check for removed devices  
                removed_mountpoints = self._last_devices - current_mountpoints
                for mountpoint in removed_mountpoints:
                    self.log(f"Device removed: {mountpoint}")
                    self._trigger_callbacks('removed', mountpoint)
                
                self._last_devices = current_mountpoints
                
            except Exception as e:
                self.log(f"Error in polling loop: {e}")
            
            # Wait for next poll
            time.sleep(self._poll_interval)
    
    def _trigger_callbacks(self, event_type: str, data) -> None:
        """Trigger callbacks for a specific event type."""
        for callback_type, callback in self._device_callbacks:
            if callback_type == event_type:
                try:
                    callback(data)
                except Exception as e:
                    self.log(f"Error in callback: {e}")


def main():
    """Command-line interface for USB detection."""
    parser = argparse.ArgumentParser(description="Cross-platform USB detection via psutil")
    parser.add_argument("--watch", type=float, default=0.0,
                       help="Poll every N seconds (0 = run once)")
    parser.add_argument("--verify-diskutil", action="store_true",
                       help="macOS: confirm with diskutil that device is external/removable")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    detector = USBDetector(verbose=args.verbose)
    
    if args.watch > 0:
        print(f"Starting USB device monitoring (polling every {args.watch}s)...")
        print("Press Ctrl+C to stop")
        
        def on_added(device):
            print(f"[ADDED] {device['device']} -> {device['mountpoint']}")
            
        def on_removed(mountpoint):
            print(f"[REMOVED] {mountpoint}")
        
        try:
            detector.start_polling(
                interval=args.watch,
                on_device_added=on_added,
                on_device_removed=on_removed
            )
            
            # Keep main thread alive
            while detector._polling_active:
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            detector.stop_polling()
    else:
        # Single detection
        devices = detector.detect_usb_devices(verify_with_diskutil=args.verify_diskutil)
        print(json.dumps(devices, indent=2))
        
        if not devices:
            print("No removable USB devices detected.")
        else:
            print(f"\nFound {len(devices)} removable device(s):")
            for i, device in enumerate(devices, 1):
                print(f"\nDevice {i}:")
                print(detector.format_device_info(device))


if __name__ == "__main__":
    main()