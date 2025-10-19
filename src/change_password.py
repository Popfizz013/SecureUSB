from auth_manager import AuthManager
from pathlib import Path
import json
import hashlib

if __name__ == "__main__":
    device_path = "test_device"  # or your actual device path
    meta_file = Path(device_path) / ".secureusb_meta.json"
    am = AuthManager(device_path)

    # Ensure device folder exists
    meta_file.parent.mkdir(parents=True, exist_ok=True)

    # Prompt for new password
    new_pw = am.prompt_for_password(confirm=True, visible=True)

    # Generate salt and key
    salt, key = am.create_auth_data(new_pw)

    # Hash the key for storage
    key_hash = hashlib.sha256(key).digest()

    # Prepare metadata
    metadata = {
        "salt": salt.hex(),
        "key_hash": key_hash.hex()
    }

    # Write metadata
    with open(meta_file, "w") as f:
        json.dump(metadata, f, indent=4)

    print("✅ Password updated successfully!")
