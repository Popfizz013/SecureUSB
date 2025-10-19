"""
Minimal USB/removable volume detection using psutil.

Run once:
  python tools/usb_detect_psutil.py

Poll every 2s:
  python tools/usb_detect_psutil.py --watch 2
"""
import argparse
import json
import time
import psutil
import platform

# Heuristic: common removable FS types used on USBs across OSes
LIKELY_REMOVABLE_FS = {
    "vfat", "exfat", "fat", "fat32", "msdos",   # Windows/Linux USB defaults
    "ntfs",                                     # many USBs are NTFS
    "hfs", "apfs"                               # mac-formatted external drives
}

# Minimal ignore list to avoid noisy system mounts
IGNORED_MOUNTPOINTS = {"/", "/System", "/private/var", "/run", "/boot", "/efi"}

def list_mounts():
    """Return a list of dicts describing likely-removable mounts."""
    devices = []
    for p in psutil.disk_partitions(all=False):
        fstype = (p.fstype or "").lower()
        mp = p.mountpoint
        # Skip obvious system mounts
        if mp in IGNORED_MOUNTPOINTS:
            continue
        # Score based on FS type heuristic
        score = 1 if fstype in LIKELY_REMOVABLE_FS else 0
        devices.append({
            "device": getattr(p, "device", ""),
            "mountpoint": mp,
            "fstype": fstype,
            "opts": p.opts,
            "score": score,             # >=1 suggests “likely removable”
            "platform": platform.system(),
        })
    return devices

def main():
    ap = argparse.ArgumentParser(description="Minimal USB detection via psutil")
    ap.add_argument("--watch", type=float, default=0.0,
                    help="poll every N seconds (0 => run once)")
    args = ap.parse_args()

    prev = set()
    while True:
        items = list_mounts()
        curr = set(d["mountpoint"] for d in items)
        print(json.dumps(items, indent=2))
        if prev:
            added = sorted(curr - prev)
            removed = sorted(prev - curr)
            if added:
                print("Added:", ", ".join(added))
            if removed:
                print("Removed:", ", ".join(removed))
        prev = curr
        if args.watch <= 0:
            break
        time.sleep(args.watch)

if __name__ == "__main__":
    main()