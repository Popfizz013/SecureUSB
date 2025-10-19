# 🔒SecureUSB

SecureUSB is a cross-platform Python app that provides secure authentication, encryption, and decryption for USB devices. It integrates USB detection, password-based authentication, AES-256-GCM encryption, and a user-friendly CLI for managing USB security.

🚀 Features:
 1. USB Detection & Authentication
        Real-time USB insertion/removal detection on windows & macOS
        Password-based authentication with PBKDF2 key derivation
        Salted and hashed keys for secure verification
        Device metadata tracking with UUID
        Multi-device management

 2. Enterprise-Grade Security
        AES-256-GCM encryption for files and folders
        Batch encryption/decryption with progress visualization
        File integrity verification with SHA-256

 3. Progress Visualization
        Real-time progress bars with tqdm
        File-by-file operation feedback
        Detailed operation statistics
        Error reporting and recovery


🔧 How It Works
Encryption Process

USB Detection → Automatically detects inserted USB drives
Authentication → User enters password (min 8 characters)
Key Derivation → PBKDF2 derives 256-bit key from password
Metadata Creation → Generates UUID and stores device info
File Encryption → Encrypts files using AES-256-GCM
Secure Deletion → Original files are securely removed

Decryption Process

USB Detection → Detects encrypted USB drive
Metadata Loading → Reads device UUID and salt
Authentication → Verifies password (3 attempts max)
Key Derivation → Recreates encryption key from password
File Decryption → Decrypts .enc files back to originals
Access Granted → Files are accessible in plain form
 
🚀 Quick & Easy 

Installation

# instructions here! 

bash# Clone the repository
git clone https://github.com/yourusername/SecureUSB.git
cd SecureUSB

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

📋 Requirements

Python 3.8+
cryptography - AES-256-GCM encryption
psutil - Cross-platform USB detection
pyudev - Advanced Linux USB detection
tqdm - Progress bar visualization
tkinter - GUI interface (included with Python)

Install all dependencies: