"""
Minimal removable volume detection using psutil with macOS-friendly filters.

Run once:
  python tools/usb_detect_psutil.py

Poll every 2s:
  python tools/usb_detect_psutil.py --watch 2

Stricter macOS verification (uses `diskutil info` if present):
  python tools/usb_detect_psutil.py --verify-diskutil
"""
import argparse
import json
import os
import platform
import subprocess
import time

import psutil

LIKELY_REMOVABLE_FS = {"vfat", "exfat", "fat", "fat32", "msdos", "ntfs", "hfs", "apfs"}
MAC_USER_VOLUME_PREFIX = "/Volumes/"
MAC_EXCLUDE_BASENAMES = {"Recovery"}  # add more if needed (e.g., "Macintosh HD")

def _darwin_user_visible(p) -> bool:
    # Only keep items mounted under /Volumes/<Name>, excluding known system volumes
    mp = p.mountpoint
    if not mp.startswith(MAC_USER_VOLUME_PREFIX):
        return False
    base = os.path.basename(mp.rstrip("/"))
    if base in MAC_EXCLUDE_BASENAMES:
        return False
    return True

def _diskutil_external_or_removable(dev: str) -> bool:
    # Optional stronger check on macOS: parse `diskutil info <dev>`
    try:
        out = subprocess.run(
            ["/usr/sbin/diskutil", "info", dev],
            capture_output=True, text=True, check=False
        ).stdout
    except Exception:
        return False
    text = out or ""
    # Any of these hints are good enough for a demo
    good_hints = ("External:               Yes",
                  "Device Location:        External",
                  "Removable Media:        Yes",
                  "Removable Media:        Removable",
                  "Protocol:               USB")
    return any(h in text for h in good_hints)

def list_mounts(verify_diskutil: bool = False):
    devices = []
    is_darwin = platform.system() == "Darwin"
    for p in psutil.disk_partitions(all=False):
        fstype = (p.fstype or "").lower()
        mp = p.mountpoint
        dev = getattr(p, "device", "")

        # Always skip weird virtual mounts or non-local root-ish things
        if not fstype or fstype == "nullfs":
            continue

        # Heuristic FS filter
        if fstype not in LIKELY_REMOVABLE_FS:
            continue

        if is_darwin:
            # Only keep user-visible volumes under /Volumes/<Name>
            if not _darwin_user_visible(p):
                continue
            if verify_diskutil and dev:
                if not _diskutil_external_or_removable(dev):
                    # It might be a DMG or internal; skip it.
                    continue

        devices.append({
            "device": dev,
            "mountpoint": mp,
            "fstype": fstype,
        })
    return devices

def main():
    ap = argparse.ArgumentParser(description="Minimal USB detection via psutil")
    ap.add_argument("--watch", type=float, default=0.0,
                    help="poll every N seconds (0 => run once)")
    ap.add_argument("--verify-diskutil", action="store_true",
                    help="macOS: confirm with `diskutil info` that device is external/removable")
    args = ap.parse_args()

    prev = set()
    while True:
        items = list_mounts(verify_diskutil=args.verify_diskutil)
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