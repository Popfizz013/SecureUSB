# src/usb_detector.py
from __future__ import annotations
import os
import platform
import subprocess
import plistlib
import time
import threading
from typing import List, Dict, Callable, Optional

try:
    import psutil  # type: ignore
except Exception:
    psutil = None

# --------------- psutil normalization ---------------
def _psutil_partitions() -> List[Dict]:
    out: List[Dict] = []
    if psutil is None:
        return out
    for p in psutil.disk_partitions(all=False):
        out.append({
            "device": getattr(p, "device", "") or "",
            "mountpoint": getattr(p, "mountpoint", "") or "",
            "fstype": (getattr(p, "fstype", "") or "").lower(),
            "opts": getattr(p, "opts", "") or "",
        })
    return out

# --------------- macOS helpers ---------------
def _diskutil_info_plist(target: str) -> Dict:
    try:
        cp = subprocess.run(
            ["diskutil", "info", "-plist", target],
            check=True, capture_output=True, text=False
        )
        return plistlib.loads(cp.stdout or b"")
    except Exception:
        return {}

def _is_external_usb(info: Dict) -> bool:
    # We require External/Removable AND USB bus/protocol
    s = lambda x: (str(x or "")).strip().lower()
    internal = bool(info.get("Internal"))
    device_location = s(info.get("DeviceLocation"))  # 'External'/'Internal'
    bus = s(info.get("BusProtocol")) or s(info.get("Protocol"))  # e.g., 'usb'
    removable = bool(info.get("RemovableMedia") or info.get("Removable") or info.get("MediaRemovable"))
    is_external = (device_location == "external") or (not internal)
    is_usb = ("usb" in bus)
    return (is_external or removable) and is_usb and (not internal)

def _looks_like_user_volume(mp: str) -> bool:
    if not mp or not mp.startswith("/Volumes/"):
        return False
    base = os.path.basename(mp).strip().lower()
    if base in {"recovery", "preboot", "update", "vm"}:
        return False
    if mp.startswith("/System/Volumes/"):
        return False
    return True

def _darwin_detect_strict() -> List[Dict]:
    result: List[Dict] = []
    for p in _psutil_partitions():
        mp = p.get("mountpoint") or ""
        if not _looks_like_user_volume(mp):
            continue
        target = p.get("device") or mp
        info = _diskutil_info_plist(target)
        if not info:
            continue
        if not _is_external_usb(info):
            continue
        result.append({
            "device": p.get("device", ""),
            "mountpoint": mp,
            "fstype": p.get("fstype", ""),
            "opts": p.get("opts", ""),
            "platform": "Darwin",
        })
    return result

# --------------- Windows helpers ---------------
def _windows_removable() -> List[Dict]:
    """Return only drives where GetDriveTypeW(root) == DRIVE_REMOVABLE."""
    out: List[Dict] = []
    try:
        import psutil  # type: ignore
    except Exception:
        return out

    import ctypes, string
    DRIVE_REMOVABLE = 2
    GetDriveTypeW = getattr(ctypes.windll.kernel32, "GetDriveTypeW", None)
    if GetDriveTypeW is None:
        return out

    for p in psutil.disk_partitions(all=False):
        mp = getattr(p, "mountpoint", "")
        try:
            if mp and GetDriveTypeW(mp) == DRIVE_REMOVABLE:
                out.append({
                    "device": getattr(p, "device", ""),
                    "mountpoint": mp,
                    "fstype": (getattr(p, "fstype", "") or "").lower(),
                    "opts": getattr(p, "opts", "") or "",
                    "platform": "Windows",
                })
        except Exception:
            continue
    return out

# --------------- Linux / generic ---------------
def _generic_candidates() -> List[Dict]:
    """Conservative fallback for non-mac/non-windows."""
    LIKELY_FS = {"vfat", "exfat", "fat", "fat32", "msdos", "ntfs", "hfs", "apfs"}
    out: List[Dict] = []
    for p in _psutil_partitions():
        fs = p.get("fstype", "")
        mp = p.get("mountpoint", "")
        if fs not in LIKELY_FS:
            continue
        # skip obvious system paths
        if mp in ("/", "/boot", "/home", "/System", "/System/Volumes/Data"):
            continue
        out.append({**p, "platform": platform.system()})
    return out

# --------------- Public API ---------------
class USBDetector:
    """
    Cross-platform USB detection.
    Returns list of dicts: {"device","mountpoint","fstype","opts","platform"}.
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize USB detector.
        
        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose
        self._polling_active = False
        self._polling_thread = None
        self._previous_devices = set()

    def detect_usb_devices(self, verify_with_diskutil: bool = True) -> List[Dict]:
        sysname = platform.system()
        if sysname == "Darwin":
            if verify_with_diskutil:
                devices = _darwin_detect_strict()
            else:
                # non-verified path still hides APFS internals
                devices = []
                for p in _psutil_partitions():
                    mp = p.get("mountpoint") or ""
                    if not _looks_like_user_volume(mp):
                        continue
                    devices.append({**p, "platform": "Darwin"})
        elif sysname == "Windows":
            devices = _windows_removable()
        else:
            # Linux/other
            devices = _generic_candidates()
        
        # Add size information
        for device in devices:
            try:
                if psutil and device.get('mountpoint'):
                    usage = psutil.disk_usage(device['mountpoint'])
                    device['total_size'] = usage.total
                    device['free_size'] = usage.free
                    device['used_size'] = usage.used
            except Exception:
                # If we can't get size info, just continue
                pass
        
        return devices

    def format_device_info(self, device: Dict) -> str:
        """
        Format device information for display.
        
        Args:
            device: Device dictionary
            
        Returns:
            Formatted device information string
        """
        lines = [
            f"  Device: {device.get('device', 'Unknown')}",
            f"  Mount Point: {device.get('mountpoint', 'Unknown')}",
            f"  Filesystem: {device.get('fstype', 'unknown').upper()}",
        ]
        
        if 'total_size' in device and isinstance(device['total_size'], (int, float)):
            total_gb = device['total_size'] / (1024**3)
            free_gb = device.get('free_size', 0) / (1024**3)
            lines.append(f"  Size: {total_gb:.2f} GB ({free_gb:.2f} GB free)")
        
        if 'platform' in device:
            lines.append(f"  Platform: {device['platform']}")
            
        return "\n".join(lines)

    def is_mounted(self, device_path: str) -> bool:
        """
        Check if a device is mounted and accessible.
        
        Args:
            device_path: Path to check (device path or mount point)
            
        Returns:
            True if mounted and accessible, False otherwise
        """
        # Check if it's a mount point
        if os.path.ismount(device_path):
            return True
        
        # Check if it's a device that's currently mounted
        devices = self.detect_usb_devices()
        for device in devices:
            if device['device'] == device_path or device['mountpoint'] == device_path:
                return True
        
        # Check if the path exists and is accessible
        try:
            return os.path.exists(device_path) and os.access(device_path, os.R_OK)
        except Exception:
            return False

    def start_polling(self, interval: float, on_device_added: Optional[Callable] = None, 
                     on_device_removed: Optional[Callable] = None) -> None:
        """
        Start polling for USB device changes.
        
        Args:
            interval: Polling interval in seconds
            on_device_added: Callback for when a device is added
            on_device_removed: Callback for when a device is removed
        """
        if self._polling_active:
            return
        
        self._polling_active = True
        self._previous_devices = set()
        
        # Get initial device list
        initial_devices = self.detect_usb_devices()
        for device in initial_devices:
            self._previous_devices.add(device['mountpoint'])
        
        def poll_worker():
            while self._polling_active:
                try:
                    current_devices = self.detect_usb_devices()
                    current_mountpoints = set(device['mountpoint'] for device in current_devices)
                    
                    # Check for added devices
                    added_mountpoints = current_mountpoints - self._previous_devices
                    for mountpoint in added_mountpoints:
                        device = next((d for d in current_devices if d['mountpoint'] == mountpoint), None)
                        if device and on_device_added:
                            on_device_added(device)
                    
                    # Check for removed devices
                    removed_mountpoints = self._previous_devices - current_mountpoints
                    for mountpoint in removed_mountpoints:
                        if on_device_removed:
                            on_device_removed(mountpoint)
                    
                    self._previous_devices = current_mountpoints
                    
                except Exception as e:
                    if self.verbose:
                        print(f"Error during polling: {e}")
                
                time.sleep(interval)
        
        self._polling_thread = threading.Thread(target=poll_worker, daemon=True)
        self._polling_thread.start()

    def stop_polling(self) -> None:
        """Stop USB device polling."""
        self._polling_active = False
        if self._polling_thread and self._polling_thread.is_alive():
            self._polling_thread.join(timeout=2.0)