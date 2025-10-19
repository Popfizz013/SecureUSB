import getpass
import time

MAX_ATTEMPTS = 3

def verify_password(password):
    # Temporary stub for testing
    return password == "test123"

def prompt_password():
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        password = getpass.getpass("Enter your USB password: ")
        if verify_password(password):
            print("✅ Authentication successful!")
            return True
        else:
            attempts += 1
            print(f"❌ Incorrect password. {MAX_ATTEMPTS - attempts} attempts left.")
            time.sleep(1)
    print("🔒 Maximum attempts reached. Access denied.")
    return False

def feedback(status):
    messages = {
        "detecting": "🔍 Detecting USB...",
        "authenticating": "🔑 Verifying password...",
        "ready": "✅ USB ready for encryption/decryption."
    }
    print(messages.get(status, "…"))

def dummy_usb_insert_event():
    print("USB inserted!")
    feedback("authenticating")
    prompt_password()

if __name__ == "__main__":
    dummy_usb_insert_event()