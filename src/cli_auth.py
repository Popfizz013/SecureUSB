# src/cli_auth.py
from pathlib import Path
import time

from auth_manager import AuthManager  # make sure auth_manager.py is in the same folder

MAX_ATTEMPTS = 3

def feedback(status: str):
    messages = {
        "detecting": "🔍 Detecting USB...",
        "authenticating": "🔑 Verifying password...",
        "ready": "✅ USB ready for encryption/decryption.",
        "denied": "🔒 Access denied."
    }
    print(messages.get(status, "…"))

def prompt_visible_password_and_verify(am: AuthManager, metadata_path: Path) -> bool:
    """
    Prompt user for a visible password and verify against metadata at metadata_path.
    Returns True on success, False otherwise.
    """
    # Load metadata first (raises if missing)
    try:
        meta = am.load_metadata(metadata_file=metadata_path)
    except FileNotFoundError:
        print("No metadata file found at", metadata_path)
        return False

    attempts = 0
    while attempts < MAX_ATTEMPTS:
        # visible input for testing / development
        password = input("Enter your USB password (visible): ")
        if am.verify_password(password, meta):
            print("✅ Authentication successful!")
            return True
        else:
            attempts += 1
            print(f"❌ Incorrect password. {MAX_ATTEMPTS - attempts} attempts left.")
            time.sleep(1)

    print("🔒 Maximum attempts reached. Access denied.")
    return False


def dummy_usb_insert_event(am: AuthManager, metadata_path: Path):
    print("USB inserted (dummy)!")
    feedback("authenticating")
    ok = prompt_visible_password_and_verify(am, metadata_path)
    if ok:
        feedback("ready")
    else:
        feedback("denied")


if __name__ == "__main__":
    # demo/test using a local folder as the "device"
    dev = Path("./test_device")
    meta_file = dev / ".secureusb_meta.json"

    dev.mkdir(parents=True, exist_ok=True)

    am = AuthManager(str(dev))
    # If metadata doesn't exist, create one interactively (visible password)
    if not meta_file.exists():
        print("No metadata found. Creating test metadata.")
        # create metadata with visible prompts (confirm)
        pw = am.prompt_for_password(confirm=True, visible=True)
        am.create_and_store_metadata(pw, metadata_file=meta_file)

    # Run the dummy insert flow (asks for password and verifies)
    dummy_usb_insert_event(am, metadata_file)