# src/ui/app.py
from __future__ import annotations
import os, sys, time, traceback, threading, queue, platform, ctypes, string
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Silence macOS system Tk warning
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

# Make imports work whether you run "python -m src.ui.app" or directly
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Repo modules (these names match your repo)
from src.usb_detector import USBDetector
from src.auth_manager import AuthManager
from src.crypto_engine import encrypt_file, decrypt_file, CryptoEngine
from src.utils.file_utils import FileUtils

APP_TITLE = "SecureUSB (Tkinter)"
META_FILENAME = ".secureusb_meta.json"
POLL_MS = 1500  # auto-refresh every 1.5s

# OS/FS noise to ignore during encrypt/decrypt
EXCLUDED_DIRS = {
    "System Volume Information",
    "$RECYCLE.BIN",
    ".Spotlight-V100",
    ".Trashes",
    ".fseventsd",
    "__MACOSX",
    META_FILENAME,
}
EXCLUDED_FILES = {
    ".DS_Store",
    "Thumbs.db",
}

# ---------------- helpers (file walking, filters) ----------------
def walk_files(root: str):
    """Yield plaintext files to encrypt (skip metadata, .enc, OS junk)."""
    for dp, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for n in filenames:
            p = os.path.join(dp, n)
            if not os.path.isfile(p):
                continue
            if p.endswith(".enc"):
                continue
            base = os.path.basename(p)
            # Skip metadata, Apple resource forks, and OS noise
            if base == META_FILENAME or base in EXCLUDED_FILES or base.startswith("._"):
                continue
            yield p

def walk_enc_files(root: str):
    """Yield encrypted files to decrypt (.enc only)."""
    for dp, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for n in filenames:
            p = os.path.join(dp, n)
            if os.path.isfile(p) and p.endswith(".enc"):
                yield p

def _filter_macos_user_vols(mounts: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Only keep true user volumes on macOS (hide APFS internals like /Volumes/Recovery)."""
    if platform.system() != "Darwin":
        return mounts
    keep = []
    for label, mp in mounts:
        if not mp.startswith("/Volumes/"):
            continue
        base = os.path.basename(mp).lower()
        if base in {"recovery", "preboot", "update", "vm"}:
            continue
        if mp.startswith("/System/Volumes/"):
            continue
        keep.append((label, mp))
    return keep

def _windows_removable_mounts_psutil() -> list[tuple[str, str]]:
    """
    Windows: enumerate psutil partitions but keep only drives where
    GetDriveTypeW(root) == DRIVE_REMOVABLE (2).
    """
    out: list[tuple[str, str]] = []
    try:
        import psutil  # type: ignore
    except Exception:
        psutil = None

    DRIVE_REMOVABLE = 2
    GetDriveTypeW = getattr(ctypes.windll.kernel32, "GetDriveTypeW", None)

    if psutil is None or GetDriveTypeW is None:
        # best-effort fallback: letters A:..Z: with removable type check if possible
        for letter in string.ascii_uppercase:
            root = f"{letter}:\\"
            try:
                if os.path.exists(root) and GetDriveTypeW and GetDriveTypeW(root) == DRIVE_REMOVABLE:
                    out.append((root, root))
            except Exception:
                pass
        return out

    for p in psutil.disk_partitions(all=False):
        mp = p.mountpoint  # e.g. 'D:\\'
        try:
            if mp and GetDriveTypeW(mp) == DRIVE_REMOVABLE:
                dev = getattr(p, "device", "")
                fstype = (getattr(p, "fstype", "") or "").lower()
                label = f"{mp} ({dev}, {fstype})" if (dev or fstype) else mp
                out.append((label, mp))
        except Exception:
            # ignore drives we can’t query
            continue
    return out

# ---------------- detection wrapper for the GUI ----------------
def list_usb_mounts_with_logs(log_cb) -> list[tuple[str, str]]:
    """
    Returns [(label, mountpoint)].
    macOS: trust diskutil-verified results only (prevents stale entries on eject).
    Windows: only drives with DRIVE_REMOVABLE.
    Linux/other: best-effort psutil/detector.
    """
    detector = USBDetector()
    tried = []
    sysname = platform.system()

    # --- macOS ---
    if sysname == "Darwin":
        try:
            devs = detector.detect_usb_devices(verify_with_diskutil=True) or []
            tried.append(f"USBDetector(verify_with_diskutil=True) -> {len(devs)}")
        except Exception as e:
            tried.append(f"USBDetector(verify_with_diskutil=True) -> ERROR {e}")
            devs = []

        mounts = []
        for d in devs:
            mp  = d.get("mountpoint") or ""
            dev = d.get("device")     or ""
            fs  = d.get("fstype")     or ""
            if not mp:
                continue
            label = f"{mp} ({dev}, {fs})" if (dev or fs) else mp
            mounts.append((label, mp))

        mounts = _filter_macos_user_vols(mounts)
        log_cb(" | ".join(tried))
        return mounts

    # --- Windows ---
    if sysname == "Windows":
        mounts = _windows_removable_mounts_psutil()
        tried.append(f"windows removable -> {len(mounts)}")
        log_cb(" | ".join(tried))
        return mounts

    # --- Linux / other ---
    try:
        devs = detector.detect_usb_devices(verify_with_diskutil=False) or []
        tried.append("generic detect -> %d" % len(devs))
        if devs:
            mounts = []
            for d in devs:
                mp  = d.get("mountpoint") or ""
                dev = d.get("device")     or ""
                fs  = d.get("fstype")     or ""
                if mp:
                    label = f"{mp} ({dev}, {fs})" if (dev or fs) else mp
                    mounts.append((label, mp))
            log_cb(" | ".join(tried))
            return mounts
    except Exception as e:
        tried.append(f"generic detect -> ERROR {e}")

    # Last resort: psutil partitions (unfiltered)
    mounts = []
    try:
        import psutil  # type: ignore
        for p in psutil.disk_partitions(all=False):
            mp = p.mountpoint
            if mp:
                dev = getattr(p, "device", "")
                fs  = (getattr(p, "fstype", "") or "").lower()
                label = f"{mp} ({dev}, {fs})" if (dev or fs) else mp
                mounts.append((label, mp))
    except Exception:
        pass
    tried.append(f"psutil fallback -> {len(mounts)}")
    log_cb(" | ".join(tried))
    return mounts

# ---------------- Tkinter App ----------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1080x800")
        self.minsize(1080, 800)

        self.mounts: list[tuple[str, str]] = []
        self._last_set: set[str] = set()
        self.log_q: "queue.Queue[str]" = queue.Queue()
        self.worker: threading.Thread | None = None

        self._build_ui()
        self._startup()
        self._refresh_mounts()
        self.after(100, self._drain_logs)
        self.after(POLL_MS, self._poll)

    def _build_ui(self):
        top = ttk.Frame(self, padding=10); top.pack(fill="x")
        ttk.Label(top, text="USB mount:").pack(side="left")
        self.cbo_mount = ttk.Combobox(top, state="readonly", width=56)
        self.cbo_mount.pack(side="left", padx=6)
        ttk.Button(top, text="Refresh", command=self._refresh_mounts).pack(side="left")

        self.auto_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Auto-refresh", variable=self.auto_var).pack(side="left", padx=(12, 0))

        ttk.Label(top, text="   Metadata:").pack(side="left", padx=(12,4))
        self.lbl_meta = ttk.Label(top, text="unknown"); self.lbl_meta.pack(side="left")
        self.cbo_mount.bind("<<ComboboxSelected>>", lambda e: self._update_meta_state())

        ttk.Separator(self).pack(fill="x", pady=(6,8))

        lf = ttk.LabelFrame(self, text="Initialize / Authenticate", padding=10); lf.pack(fill="x", padx=10)
        ttk.Label(lf, text="Username:").grid(row=0, column=0, sticky="w")
        self.ent_owner = ttk.Entry(lf, width=24); self.ent_owner.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(lf, text="Password:").grid(row=0, column=2, sticky="e")
        self.ent_pw = ttk.Entry(lf, width=24, show="•"); self.ent_pw.grid(row=0, column=3, sticky="w", padx=6)
        ttk.Button(lf, text="Init Metadata", command=self.on_init).grid(row=0, column=4, padx=6)
        ttk.Button(lf, text="Check Password", command=self.on_check).grid(row=0, column=5, padx=6)
        for i in range(6): lf.grid_columnconfigure(i, weight=1)

        act = ttk.LabelFrame(self, text="Actions", padding=10); act.pack(fill="x", padx=10, pady=(8,4))
        ttk.Button(act, text="Encrypt Folder…", command=self.on_encrypt_folder).pack(side="left", padx=4)
        ttk.Button(act, text="Encrypt Whole USB", command=self.on_encrypt_all).pack(side="left", padx=4)
        ttk.Button(act, text="Decrypt All on USB", command=self.on_decrypt_all).pack(side="left", padx=4)
        self.pb = ttk.Progressbar(act, length=320, mode="determinate", maximum=100, value=0)
        self.pb.pack(side="left", padx=10)

        logf = ttk.LabelFrame(self, text="Log", padding=8); logf.pack(fill="both", expand=True, padx=10, pady=(6,10))
        self.txt = tk.Text(logf, height=20); self.txt.pack(fill="both", expand=True)

    def _startup(self):
        self._log("Welcome to Secure USB! Please read the following steps:\n")
        self._log(" 1) Plug in your USB drive")
        self._log(" 2) Auto-refresh is ON by default. Watch to see your USB get detected.")
        self._log(" 3) [TO ENCRYPT]: Select USB → Choose a username and password → Init Metadata → Encrypt.")
        self._log(" 4) [TO DECRYPT]: Select USB → Enter your username and password → Check Password → Decrypt.\n")

    # ----- helpers
    def _select_mount(self) -> str | None:
        i = self.cbo_mount.current()
        if i < 0 or i >= len(self.mounts): return None
        return self.mounts[i][1]

    def _refresh_mounts(self):
        prev_sel = self._select_mount()
        self.mounts = list_usb_mounts_with_logs(self._log)
        self.cbo_mount["values"] = [lab for (lab, _) in self.mounts]
        if not self.mounts:
            self.cbo_mount.set("")  # clear selection when list becomes empty
        elif prev_sel and any(mp == prev_sel for _, mp in self.mounts):
            self.cbo_mount.current([mp for _, mp in self.mounts].index(prev_sel))
        elif self.mounts:
            self.cbo_mount.current(0)
        self._last_set = set(mp for _, mp in self.mounts)
        self._log(f"Found {len(self.mounts)} removable volume(s).")
        self._update_meta_state()

    def _update_meta_state(self):
        mp = self._select_mount()
        if not mp:
            self.lbl_meta.config(text="unknown"); return
        try:
            am = AuthManager(mp)
            am.load_metadata()
            self.lbl_meta.config(text="present")
        except Exception:
            self.lbl_meta.config(text="missing")

    # ----- logging / polling
    def _log(self, s: str):
        self.txt.insert("end", s + "\n"); self.txt.see("end")

    def _drain_logs(self):
        # (kept in case we move log calls to a thread in the future)
        self.after(100, self._drain_logs)

    def _poll(self):
        if self.auto_var.get():
            mounts_now = list_usb_mounts_with_logs(lambda _: None)
            curr = set(mp for _, mp in mounts_now)
            add = sorted(curr - self._last_set)
            rem = sorted(self._last_set - curr)
            for mp in add: self._log(f"USB added:   {mp}")
            for mp in rem: self._log(f"USB removed: {mp}")
            if add or rem:
                self.mounts = mounts_now
                self.cbo_mount["values"] = [lab for (lab, _) in self.mounts]
                if not self.mounts:
                    self.cbo_mount.set("")
                elif self.cbo_mount.current() == -1:
                    self.cbo_mount.current(0)
                self._update_meta_state()
            self._last_set = curr
        self.after(POLL_MS, self._poll)

    # ----- actions
    def _get_key(self, mount: str) -> bytes:
        pw = self.ent_pw.get()
        if not pw: raise ValueError("Enter a password first.")
        am = AuthManager(mount)
        md = am.load_metadata()
        if not am.verify_password(pw, md):
            raise ValueError("Incorrect password.")
        return am.get_encryption_key(pw, md)

    def on_init(self):
        mp = self._select_mount()
        if not mp: return messagebox.showwarning("Select USB", "Pick a USB mount first.")
        owner = self.ent_owner.get().strip() or os.getlogin()
        pw = self.ent_pw.get()
        if not pw: return messagebox.showwarning("Password", "Enter a password.")
        
        am = AuthManager(mp)
        
        # Check if metadata already exists
        meta_path = Path(mp) / META_FILENAME
        if meta_path.exists():
            # Check if there are encrypted files that could become inaccessible
            encrypted_files = list(walk_enc_files(mp))
            if encrypted_files:
                # Critical warning: encrypted files exist
                response = messagebox.askquestion(
                    "⚠️ DANGER - Encrypted Files Detected",
                    f"This USB drive already contains {len(encrypted_files)} encrypted files!\n\n"
                    "Re-initializing metadata will make these files PERMANENTLY INACCESSIBLE.\n"
                    "This action CANNOT be undone!\n\n"
                    "If this is your USB drive, use 'Check Password' instead to verify access.\n"
                    "If you borrowed this USB, return it to the owner first.\n\n"
                    "Are you ABSOLUTELY SURE you want to destroy the existing encrypted data?"
                )
                if response != 'yes':
                    self._log("⚠️ Metadata initialization cancelled - existing encrypted files preserved")
                    return
                self._log(f"⚠️ WARNING: User chose to overwrite metadata with {len(encrypted_files)} encrypted files present!")
            else:
                # Metadata exists but no encrypted files - safer to reinitialize
                response = messagebox.askquestion(
                    "Metadata Already Exists",
                    "This USB drive already has SecureUSB metadata.\n\n"
                    "Re-initializing will create new encryption keys.\n"
                    "Any future encrypted files will use the new password.\n\n"
                    "Continue with re-initialization?",
                    default=messagebox.NO
                )
                if response != 'yes':
                    self._log("Metadata initialization cancelled - existing metadata preserved")
                    return
        
        # Remove existing metadata if it exists (since we're overwriting with new credentials)
        if meta_path.exists():
            try:
                meta_path.unlink()
                self._log(f"Removed existing metadata file: {META_FILENAME}")
            except Exception as e:
                self._log(f"Warning: Could not remove existing metadata: {e}")
        
        # Proceed with initialization
        meta = am.create_auth_data(pw)
        meta["Username"] = owner
        am.write_metadata_atomic(meta)
        self._log(f"Initialized metadata at {mp}/{META_FILENAME}")
        self._update_meta_state()
        messagebox.showinfo("Success", "Metadata initialized.")

    def on_check(self):
        mp = self._select_mount()
        if not mp: return messagebox.showwarning("Select USB", "Pick a USB mount first.")
        am = AuthManager(mp)
        try:
            ok = am.verify_password(self.ent_pw.get(), am.load_metadata())
        except Exception as e:
            self._log(f"[ERROR] verify_password: {e}"); ok = False
        self._log(f"Password check: {'OK' if ok else 'FAILED'}")
        messagebox.showinfo("Password", "OK" if ok else "Incorrect")

    def on_encrypt_folder(self):
        mp = self._select_mount()
        if not mp: return messagebox.showwarning("Select USB", "Pick a USB mount first.")
        try:
            key = self._get_key(mp)
        except Exception as e:
            return messagebox.showerror("Auth error", str(e))
        folder = filedialog.askdirectory(title="Choose folder to encrypt", initialdir=mp, mustexist=True)
        if not folder: return
        files = list(walk_files(folder))
        if not files: return messagebox.showinfo("Nothing to do","No files to encrypt in that folder.")
        self.pb.configure(maximum=len(files), value=0)
        threading.Thread(target=self._encrypt_worker, args=(files, key), daemon=True).start()

    def on_encrypt_all(self):
        mp = self._select_mount()
        if not mp: return messagebox.showwarning("Select USB", "Pick a USB mount first.")
        try:
            key = self._get_key(mp)
        except Exception as e:
            return messagebox.showerror("Auth error", str(e))
        files = list(walk_files(mp))
        if not files: return messagebox.showinfo("Nothing to do","No files to encrypt on this USB.")
        self.pb.configure(maximum=len(files), value=0)
        threading.Thread(target=self._encrypt_worker, args=(files, key), daemon=True).start()

    def on_decrypt_all(self):
        mp = self._select_mount()
        if not mp: return messagebox.showwarning("Select USB", "Pick a USB mount first.")
        try:
            key = self._get_key(mp)
        except Exception as e:
            return messagebox.showerror("Auth error", str(e))
        files = list(walk_enc_files(mp))
        if not files: return messagebox.showinfo("Nothing to do","No .enc files found on this USB.")
        self.pb.configure(maximum=len(files), value=0)
        threading.Thread(target=self._decrypt_worker, args=(files, key), daemon=True).start()

    # workers
    def _encrypt_worker(self, files, key: bytes):
        ok = err = 0
        crypto_engine = CryptoEngine(key)
        
        for i, path in enumerate(files, 1):
            try:
                file_path = Path(path)
                
                # Skip already encrypted files
                if file_path.suffix == '.enc':
                    continue
                
                # Create encrypted version
                encrypted_path = file_path.with_suffix(file_path.suffix + '.enc')
                crypto_engine.encrypt_file(file_path, encrypted_path)
                
                # Securely delete original
                FileUtils.secure_delete(file_path)
                
                ok += 1; self._log(f"[enc] {path} -> {encrypted_path}")
            except Exception as e:
                err += 1; self._log(f"[WARN] {path}: {e}")
            self.pb.after(0, self.pb.configure, {"value": i}); time.sleep(0.003)
        self._log(f"Encryption complete: {ok} ok, {err} errors.")

    def _decrypt_worker(self, files, key: bytes):
        ok = err = 0
        crypto_engine = CryptoEngine(key)
        
        for i, path in enumerate(files, 1):
            try:
                file_path = Path(path)
                
                # Only process .enc files
                if not file_path.suffix == '.enc':
                    continue
                
                # Create decrypted version (remove .enc extension)
                original_path = file_path.with_suffix('')
                crypto_engine.decrypt_file(file_path, original_path)
                
                # Securely delete encrypted file
                FileUtils.secure_delete(file_path)
                
                ok += 1; self._log(f"[dec] {path} -> {original_path}")
            except Exception as e:
                err += 1; self._log(f"[WARN] {path}: {e}")
            self.pb.after(0, self.pb.configure, {"value": i}); time.sleep(0.003)
        self._log(f"Decryption complete: {ok} ok, {err} errors.")


def main():
    App().mainloop()

if __name__ == "__main__":
    main()