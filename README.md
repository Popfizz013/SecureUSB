# SecureUSB

SecureUSB is a cross-platform app that provides secure authentication, encryption, and decryption for USB devices. It integrates USB detection, password-based authentication, AES-256-GCM encryption, and a user-friendly CLI for managing USB security.

### Meet the Team!!
Liam – Systems Architect & Team Lead  \
Michael – Encryption & Metadata  \
Rahil – UI & CLI Developer 

# Features:
 ### 1. USB Detection & Authentication
        Real-time USB insertion/removal detection on windows & macOS
        Password-based authentication with PBKDF2 key derivation
        Salted and hashed keys for secure verification
        Device metadata tracking with UUID
        Multi-device management

 ### 2. Enterprise-Grade Security
        AES-256-GCM encryption for files and folders
        Batch encryption/decryption with progress visualization
        Retry-limited password authentication
        File integrity verification with SHA-256

 ### 3. Progress Visualization
        Real-time progress bars with tqdm
        File-by-file operation feedback
        Detailed operation statistics
        Error reporting and recovery


# How It Works

### The Encryption Process

USB Detection → Automatically detects inserted USB drives  
Authentication → User enters password (min 8 characters)  
Key Derivation → PBKDF2 derives 256-bit key from password  
Metadata Creation → Generates UUID and stores device info  
File Encryption → Encrypts files using AES-256-GCM  
Secure Deletion → Original files are securely removed  

### The Decryption Process

USB Detection → Detects encrypted USB drive  
Metadata Loading → Reads device UUID and salt  
Authentication → Verifies password (3 attempts max)  
Key Derivation → Recreates encryption key from password  
File Decryption → Decrypts .enc files back to originals  
Access Granted → Files are accessible in plain form  
 
# Quick & Easy Installation and use

## Command Line Interface (CLI)

SecureUSB comes with a powerful command-line interface that allows users to detect, monitor, encrypt, and decrypt USB devices with ease.

### Usage
 python src/main.py [-h] [--detect] [--monitor INTERVAL] [--encrypt DEVICE] [--decrypt [DEVICE]] [--status] [--gui] [--verbose]


### Description:
SecureUSB - Secure USB Drive Protection System

| Option               | Description                                                                  |
| -------------------- | ---------------------------------------------------------------------------- |
| `-h, --help`         | Show this help message and exit                                              |
| `--detect`           | Detect and list connected USB devices                                        |
| `--monitor INTERVAL` | Monitor USB devices with polling interval in seconds (e.g., `--monitor 2.0`) |
| `--encrypt DEVICE`   | Encrypt the specified USB device                                             |
| `--decrypt [DEVICE]` | Decrypt the specified USB device (or auto-detect if no device specified)     |
| `--status`           | Show encryption status of all detected USB devices                           |
| `--gui`              | Launch the GUI interface                                                     |
| `--verbose, -v`      | Enable verbose output                                                        |

### Example:
        python src/main.py --detect              # Detect connected USB devices once  
        python src/main.py --monitor 2.0         # Monitor USB devices (poll every 2 seconds)  
        python src/main.py --status              # Show encryption status of all USB devices   
        python src/main.py --encrypt "D:/"       # Encrypt all files on USB drive D:/  
        python src/main.py --decrypt             # Auto-detect and decrypt encrypted USB device  

# user-guide: 
**Download the latest executable here:**  
https://github.com/Popfizz013/SecureUSB/releases/tag/v1.0.0

- **Windows:** download the `.exe`, then double-click to run.
  - If SmartScreen warns you, click **More info → Run anyway** (we don’t have code-signing yet).
- **macOS (Apple Silicon/Intel):** download the `.app` or `.dmg`.
  - If Gatekeeper blocks it: **Right-click → Open → Open** once to whitelist the app.

> Tip: Always prefer the newest file attached to that release page (look for the highest version or most recent upload timestamp).

---

## Running

1. Plug in your USB drive.
2. Launch **SecureUSB**.
3. Select your drive, enter **Username** and **Password**, and click **Init Metadata** once for first-time setup.
4. Use **Encrypt Folder… / Encrypt Whole USB** to protect files, or **Decrypt All on USB** to restore.

> Advanced users can still run from source with Python (`python -m src.ui.app`), but the executable above is the easiest way to get started.
