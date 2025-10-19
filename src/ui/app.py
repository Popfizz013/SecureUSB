# src/ui/app.py
from __future__ import annotations
import os, sys, threading, queue, time, traceback, platform
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Silence macOS system Tk warning
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

# Ensure imports work whether run as module or directly
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Repo modules
from src.usb_detector import USBDetector
from src.auth_manager import AuthManager
from src.crypto_engine import encrypt_file, decrypt_file

META_FILENAME = ".secureusb_meta.json"
APP_TITLE = "SecureUSB (Tkinter)"
EXCLUDED_DIRS = {"System Volume Information", "$RECYCLE.BIN", META_FILENAME}
POLL_MS = 1500  # auto-refresh every 1.5s

# ---------- helpers ----------
def walk_files(root: str):
    for dp, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for n in filenames:
            if n in EXCLUDED_DIRS:
                continue
            p = os.path.join(dp, n)
            if os.path.isfile(p) and not p.endswith(".enc"):
                yield p

def walk_enc_files(root: str):
    for dp, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDED_DIRS]
        for n in filenames:
            p = os.path.join(dp, n)
            if os.path.isfile(p) and p.endswith(".enc"):
                yield p

def _psutil_mounts_mac_only_volumes():
    try:
        import psutil
    except Exception:
        return []
    out = []
    is_darwin = (platform.system() == "Darwin")
    for p in psutil.disk_partitions(all=False):
        mp = p.mountpoint
        if is_darwin and not mp.startswith("/Volumes/"):
            continue  # hide APFS internals
        fstype = (p.fstype or "").lower()
        dev = getattr(p, "device", "")
        label = f"{mp} ({dev}, {fstype})" if (dev or fstype) else mp
        out.append((label, mp))
    return out

def list_usb_mounts_with_logs(log_cb) -> list[tuple[str, str]]:
    """Try USBDetector (with and without diskutil), then psutil fallback."""
    detector = USBDetector()
    tried = []
    for flag in (True, False):
        try:
            devs = detector.detect_usb_devices(verify_with_diskutil=flag) or []
            tried.append(f"USBDetector(verify_with_diskutil={flag}) -> {len(devs)}")
            if devs:
                mounts = []
                for d in devs:
                    mp = d.get("mountpoint") or ""
                    dev = d.get("device") or ""
                    fs  = d.get("fstype") or ""
                    if mp:
                        label = f"{mp} ({dev}, {fs})" if (dev or fs) else mp
                        mounts.append((label, mp))
                log_cb(" | ".join(tried))
                return mounts
        except Exception as e:
            tried.append(f"USBDetector(flag={flag}) -> ERROR {e}")
    mounts = _psutil_mounts_mac_only_volumes()
    tried.append(f"psutil fallback -> {len(mounts)}")
    log_cb(" | ".join(tried))
    return mounts

# ---------- App ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x580"); self.minsize(780, 480)

        self.mounts: list[tuple[str,str]] = []
        self._last_mount_set: set[str] = set()
        self.log_q: "queue.Queue[str]" = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()

        self._build_ui()
        self._startup_message()
        self._refresh_mounts()
        self.after(100, self._drain_logs)
        self.after(POLL_MS, self._poll_tick)

    def _build_ui(self):
        top = ttk.Frame(self, padding=12); top.pack(fill="x")
        ttk.Label(top, text="USB mount:").pack(side="left")
        self.cbo_mount = ttk.Combobox(top, state="readonly", width=52)
        self.cbo_mount.pack(side="left", padx=6)
        ttk.Button(top, text="Refresh", command=self._refresh_mounts).pack(side="left")

        self.auto_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="Auto-refresh", variable=self.auto_var).pack(side="left", padx=(12, 0))

        ttk.Label(top, text="   Metadata:").pack(side="left", padx=(12,4))
        self.lbl_meta = ttk.Label(top, text="unknown"); self.lbl_meta.pack(side="left")
        self.cbo_mount.bind("<<ComboboxSelected>>", lambda e: self._update_meta_state())

        ttk.Separator(self).pack(fill="x", pady=(6,8))

        lf = ttk.LabelFrame(self, text="Initialize / Authenticate", padding=12); lf.pack(fill="x", padx=12)
        ttk.Label(lf, text="Owner:").grid(row=0, column=0, sticky="w")
        self.ent_owner = ttk.Entry(lf, width=24); self.ent_owner.grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(lf, text="Password:").grid(row=0, column=2, sticky="e")
        self.ent_pw = ttk.Entry(lf, width=24, show="•"); self.ent_pw.grid(row=0, column=3, sticky="w", padx=6)
        ttk.Button(lf, text="Init Metadata", command=self.on_init).grid(row=0, column=4, padx=6)
        ttk.Button(lf, text="Check Password", command=self.on_check).grid(row=0, column=5, padx=6)
        for i in range(6): lf.grid_columnconfigure(i, weight=1)

        act = ttk.LabelFrame(self, text="Actions", padding=12); act.pack(fill="x", padx=12, pady=(6,2))
        ttk.Button(act, text="Encrypt Folder…", command=self.on_encrypt_folder).pack(side="left", padx=4)
        ttk.Button(act, text="Encrypt Whole USB", command=self.on_encrypt_all).pack(side="left", padx=4)
        ttk.Button(act, text="Decrypt All on USB", command=self.on_decrypt_all).pack(side="left", padx=4)
        self.pb = ttk.Progressbar(act, length=300, mode="determinate", maximum=100, value=0)
        self.pb.pack(side="left", padx=12)

        logf = ttk.LabelFrame(self, text="Log", padding=8); logf.pack(fill="both", expand=True, padx=12, pady=(8,10))
        self.txt = tk.Text(logf, height=18); self.txt.pack(fill="both", expand=True)

    def _startup_message(self):
        self._log("Welcome 👋  Steps:")
        self._log(" 1) Plug in your USB (on macOS it mounts under /Volumes/<name>).")
        self._log(" 2) Auto-refresh is ON. Watch the log for 'USB added/removed'.")
        self._log(" 3) Select your USB → set password → Init Metadata → Encrypt/Decrypt.")

    def _select_mount(self) -> str | None:
        i = self.cbo_mount.current()
        if i < 0 or i >= len(self.mounts): return None
        return self.mounts[i][1]

    def _refresh_mounts(self):
        prev_sel = self._select_mount()
        self.mounts = list_usb_mounts_with_logs(self._log)
        self.cbo_mount["values"] = [lab for (lab, _) in self.mounts]
        if prev_sel and any(mp == prev_sel for _, mp in self.mounts):
            self.cbo_mount.current([mp for _, mp in self.mounts].index(prev_sel))
        elif self.mounts:
            self.cbo_mount.current(0)
        curr_set = set(mp for _, mp in self.mounts)
        self._last_mount_set = curr_set
        self._log(f"Found {len(self.mounts)} removable volume(s)." if self.mounts else
                  "No removable volumes found. On macOS, your USB should appear under /Volumes.")
        self._update_meta_state()

    def _update_meta_state(self):
        mp = self._select_mount()
        if not mp:
            self.lbl_meta.config(text="unknown"); return
        am = AuthManager(mp)
        try:
            am.load_metadata(); state = "present"
        except Exception:
            state = "missing"
        self.lbl_meta.config(text=state)

    def _log(self, msg: str): self.log_q.put(msg)

    def _drain_logs(self):
        try:
            while True:
                line = self.log_q.get_nowait()
                self.txt.insert("end", line + "\n"); self.txt.see("end")
        except queue.Empty:
            pass
        self.after(100, self._drain_logs)

    def _poll_tick(self):
        if self.auto_var.get():
            mounts_now = list_usb_mounts_with_logs(lambda _: None)
            curr = set(mp for _, mp in mounts_now)
            prev = self._last_mount_set
            added = sorted(curr - prev)
            removed = sorted(prev - curr)
            if added or removed:
                for mp in added: self._log(f"USB added:   {mp}")
                for mp in removed: self._log(f"USB removed: {mp}")
                self.mounts = mounts_now
                self.cbo_mount["values"] = [lab for (lab, _) in self.mounts]
                if self.mounts and self.cbo_mount.current() == -1:
                    self.cbo_mount.current(0)
                self._last_mount_set = curr
                self._update_meta_state()
        self.after(POLL_MS, self._poll_tick)

    def _run_bg(self, target, *args):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo("Busy", "An operation is already running."); return
        self.stop_flag.clear()
        self.worker = threading.Thread(target=self._wrap_worker, args=(target, *args), daemon=True)
        self.worker.start()

    def _wrap_worker(self, fn, *args):
        try:
            fn(*args)
        except Exception as e:
            self._log("[ERROR] " + str(e)); self._log(traceback.format_exc())

    # ----- actions
    def on_init(self):
        mp = self._select_mount()
        if not mp: messagebox.showwarning("Select USB","Pick a USB mount first."); return
        owner = self.ent_owner.get().strip() or os.getlogin()
        pw = self.ent_pw.get()
        if not pw: messagebox.showwarning("Password","Enter a password."); return
        try:
            am = AuthManager(mp)
            meta = am.create_auth_data(pw)
            meta["owner"] = owner
            am.write_metadata_atomic(meta)
            self._log(f"Initialized metadata at {mp}/{META_FILENAME}")
            self._update_meta_state()
            messagebox.showinfo("Success","Metadata initialized.")
        except Exception as e:
            messagebox.showerror("Init failed", str(e))

    def on_check(self):
        mp = self._select_mount()
        if not mp: messagebox.showwarning("Select USB","Pick a USB mount first."); return
        pw = self.ent_pw.get()
        try:
            am = AuthManager(mp)
            md = am.load_metadata()
            ok = am.verify_password(pw, md)
        except Exception as e:
            self._log(f"[ERROR] verify_password: {e}"); ok = False
        self._log(f"Password check: {'OK' if ok else 'FAILED'}")
        messagebox.showinfo("Password", "OK" if ok else "Incorrect")

    def _get_key(self, mount: str) -> bytes:
        pw = self.ent_pw.get()
        if not pw: raise ValueError("Enter a password first.")
        am = AuthManager(mount)
        md = am.load_metadata()
        if not am.verify_password(pw, md):
            raise ValueError("Incorrect password.")
        return am.get_encryption_key(pw, md)

    def on_encrypt_folder(self):
        mp = self._select_mount()
        if not mp: messagebox.showwarning("Select USB","Pick a USB mount first."); return
        try:
            key = self._get_key(mp)
        except Exception as e:
            messagebox.showerror("Auth error", str(e)); return
        folder = filedialog.askdirectory(title="Choose folder to encrypt", initialdir=mp, mustexist=True)
        if not folder: return
        files = list(walk_files(folder))
        if not files: messagebox.showinfo("Nothing to do","No files to encrypt in that folder."); return
        self.pb.configure(maximum=len(files), value=0)
        self._run_bg(self._encrypt_worker, files, key)

    def on_encrypt_all(self):
        mp = self._select_mount()
        if not mp: messagebox.showwarning("Select USB","Pick a USB mount first."); return
        try:
            key = self._get_key(mp)
        except Exception as e:
            messagebox.showerror("Auth error", str(e)); return
        files = list(walk_files(mp))
        if not files: messagebox.showinfo("Nothing to do","No files to encrypt on this USB."); return
        self.pb.configure(maximum=len(files), value=0)
        self._run_bg(self._encrypt_worker, files, key)

    def on_decrypt_all(self):
        mp = self._select_mount()
        if not mp: messagebox.showwarning("Select USB","Pick a USB mount first."); return
        try:
            key = self._get_key(mp)
        except Exception as e:
            messagebox.showerror("Auth error", str(e)); return
        files = list(walk_enc_files(mp))
        if not files: messagebox.showinfo("Nothing to do","No .enc files found on this USB."); return
        self.pb.configure(maximum=len(files), value=0)
        self._run_bg(self._decrypt_worker, files, key)

    # ----- workers
    def _encrypt_worker(self, files, key: bytes):
        ok = err = 0
        for i, path in enumerate(files, 1):
            try:
                encrypt_file(path, key)
                ok += 1; self._log(f"[enc] {path}")
            except Exception as e:
                err += 1; self._log(f"[WARN] enc {path}: {e}")
            self.pb.after(0, self.pb.configure, {"value": i})
            time.sleep(0.005)
        self._log(f"Encryption complete: {ok} ok, {err} errors.")

    def _decrypt_worker(self, files, key: bytes):
        ok = err = 0
        for i, path in enumerate(files, 1):
            try:
                decrypt_file(path, key)
                ok += 1; self._log(f"[dec] {path}")
            except Exception as e:
                err += 1; self._log(f"[WARN] dec {path}: {e}")
            self.pb.after(0, self.pb.configure, {"value": i})
            time.sleep(0.005)
        self._log(f"Decryption complete: {ok} ok, {err} errors.")

def main():
    App().mainloop()

if __name__ == "__main__":
    main()