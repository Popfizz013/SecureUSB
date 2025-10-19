""""""

USB/removable volume detection using psutil.USB/removable volume detection using psutil.



This module provides USB device detection and management capabilitiesThis module provides USB device detection and management capabilities

for the SecureUSB system.for the SecureUSB system.

""""""

import argparseimport argparse

import jsonimport json

import timeimport time

import psutilimport psutil

import platformimport platform

import shutil

from typing import List, Dict, Optional, Any# Heuristic: common removable FS types used on USBs across OSes

from pathlib import PathLIKELY_REMOVABLE_FS = {

    "vfat", "exfat", "fat", "fat32", "msdos",   # Windows/Linux USB defaults

    "ntfs",                                     # many USBs are NTFS

class USBDetector:    "hfs", "apfs"                               # mac-formatted external drives

    """USB device detection and management class."""}

    

    # Heuristic: common removable FS types used on USBs across OSes# Minimal ignore list to avoid noisy system mounts

    LIKELY_REMOVABLE_FS = {IGNORED_MOUNTPOINTS = {"/", "/System", "/private/var", "/run", "/boot", "/efi"}

        "vfat", "exfat", "fat", "fat32", "msdos",   # Windows/Linux USB defaults

        "ntfs",                                     # many USBs are NTFSdef list_mounts():

        "hfs", "apfs"                               # mac-formatted external drives    """Return a list of dicts describing likely-removable mounts."""

    }    devices = []

    for p in psutil.disk_partitions(all=False):

    # Minimal ignore list to avoid noisy system mounts        fstype = (p.fstype or "").lower()

    IGNORED_MOUNTPOINTS = {"/", "/System", "/private/var", "/run", "/boot", "/efi"}        mp = p.mountpoint

            # Skip obvious system mounts

    def __init__(self, verbose: bool = False):        if mp in IGNORED_MOUNTPOINTS:

        """            continue

        Initialize USBDetector.        # Score based on FS type heuristic

                score = 1 if fstype in LIKELY_REMOVABLE_FS else 0

        Args:        devices.append({

            verbose: Enable verbose logging            "device": getattr(p, "device", ""),

        """            "mountpoint": mp,

        self.verbose = verbose            "fstype": fstype,

        self.platform = platform.system()            "opts": p.opts,

                    "score": score,             # >=1 suggests “likely removable”

    def detect_usb_devices(self) -> List[Dict[str, Any]]:            "platform": platform.system(),

        """        })

        Detect and return information about USB devices.    return devices

        

        Returns:def main():

            List of dictionaries containing device information    ap = argparse.ArgumentParser(description="Minimal USB detection via psutil")

        """    ap.add_argument("--watch", type=float, default=0.0,

        devices = []                    help="poll every N seconds (0 => run once)")

        for partition in psutil.disk_partitions(all=False):    args = ap.parse_args()

            if self.is_usb_device(partition):

                device_info = self._get_device_info(partition)    prev = set()

                devices.append(device_info)    while True:

                items = list_mounts()

        return devices        curr = set(d["mountpoint"] for d in items)

            print(json.dumps(items, indent=2))

    def is_usb_device(self, partition) -> bool:        if prev:

        """            added = sorted(curr - prev)

        Determine if a partition represents a USB device.            removed = sorted(prev - curr)

                    if added:

        Args:                print("Added:", ", ".join(added))

            partition: psutil partition object            if removed:

                            print("Removed:", ", ".join(removed))

        Returns:        prev = curr

            True if likely a USB device, False otherwise        if args.watch <= 0:

        """            break

        fstype = (partition.fstype or "").lower()        time.sleep(args.watch)

        mountpoint = partition.mountpoint

        if __name__ == "__main__":

        # Skip obvious system mounts    main()
        if mountpoint in self.IGNORED_MOUNTPOINTS:
            return False
            
        # Check if filesystem type suggests removable media
        return fstype in self.LIKELY_REMOVABLE_FS
    
    def _get_device_info(self, partition) -> Dict[str, Any]:
        """
        Get detailed information about a device partition.
        
        Args:
            partition: psutil partition object
            
        Returns:
            Dictionary with device information
        """
        fstype = (partition.fstype or "").lower()
        score = 1 if fstype in self.LIKELY_REMOVABLE_FS else 0
        
        # Get usage information if available
        try:
            usage = shutil.disk_usage(partition.mountpoint)
            size = usage.total
            free = usage.free
            used = usage.used
        except (OSError, PermissionError):
            size = free = used = 0
            
        return {
            "device": getattr(partition, "device", ""),
            "mountpoint": partition.mountpoint,
            "fstype": fstype,
            "opts": partition.opts,
            "score": score,
            "platform": self.platform,
            "size": size,
            "used": used,
            "free": free
        }
    
    def get_device_capacity(self, mountpoint: str) -> Optional[Dict[str, int]]:
        """
        Get capacity information for a specific device.
        
        Args:
            mountpoint: Device mount point
            
        Returns:
            Dictionary with size information or None if unavailable
        """
        try:
            usage = shutil.disk_usage(mountpoint)
            return {
                "total": usage.total,
                "used": usage.used,
                "free": usage.free
            }
        except (OSError, PermissionError):
            return None
    
    def is_mounted(self, device_path: str) -> bool:
        """
        Check if a device is currently mounted.
        
        Args:
            device_path: Path to the device
            
        Returns:
            True if device is mounted, False otherwise
        """
        for partition in psutil.disk_partitions():
            if partition.device == device_path:
                return True
        return False
    
    def format_device_info(self, device_info: Dict[str, Any]) -> str:
        """
        Format device information for display.
        
        Args:
            device_info: Device information dictionary
            
        Returns:
            Formatted string representation
        """
        size_gb = device_info.get('size', 0) / (1024**3)
        used_gb = device_info.get('used', 0) / (1024**3)
        free_gb = device_info.get('free', 0) / (1024**3)
        
        return (
            f"Device: {device_info['device']}\n"
            f"  Mount Point: {device_info['mountpoint']}\n"
            f"  File System: {device_info['fstype']}\n"
            f"  Size: {size_gb:.2f} GB\n"
            f"  Used: {used_gb:.2f} GB\n"
            f"  Free: {free_gb:.2f} GB\n"
            f"  Platform: {device_info['platform']}"
        )
    
    def watch_for_changes(self, interval: float = 2.0, callback=None) -> None:
        """
        Watch for USB device changes.
        
        Args:
            interval: Polling interval in seconds
            callback: Optional callback function for device changes
        """
        prev_devices = set()
        
        while True:
            current_devices = set()
            devices = self.detect_usb_devices()
            
            for device in devices:
                current_devices.add(device['mountpoint'])
            
            # Detect changes
            added = current_devices - prev_devices
            removed = prev_devices - current_devices
            
            if added or removed:
                if callback:
                    callback(added, removed, devices)
                else:
                    if added:
                        print(f"Added devices: {', '.join(added)}")
                    if removed:
                        print(f"Removed devices: {', '.join(removed)}")
            
            prev_devices = current_devices
            time.sleep(interval)


def list_mounts():
    """Legacy function for backward compatibility."""
    detector = USBDetector()
    return detector.detect_usb_devices()


def main():
    """Main function for CLI usage."""
    ap = argparse.ArgumentParser(description="USB detection via psutil")
    ap.add_argument("--watch", type=float, default=0.0,
                    help="poll every N seconds (0 => run once)")
    args = ap.parse_args()

    detector = USBDetector(verbose=True)
    
    if args.watch <= 0:
        # Run once
        devices = detector.detect_usb_devices()
        print(json.dumps(devices, indent=2))
    else:
        # Watch for changes
        detector.watch_for_changes(interval=args.watch)


if __name__ == "__main__":
    main()