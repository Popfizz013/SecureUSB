# src/usb_detector.py
from __future__ import annotations
import os
import platform
import subprocess
import plistlib
from typing import List, Dict

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

    def detect_usb_devices(self, verify_with_diskutil: bool = True) -> List[Dict]:
        sysname = platform.system()
        if sysname == "Darwin":
            if verify_with_diskutil:
                return _darwin_detect_strict()
            # non-verified path still hides APFS internals
            out = []
            for p in _psutil_partitions():
                mp = p.get("mountpoint") or ""
                if not _looks_like_user_volume(mp):
                    continue
                out.append({**p, "platform": "Darwin"})
            return out
        if sysname == "Windows":
            return _windows_removable()
        # Linux/other
        return _generic_candidates()