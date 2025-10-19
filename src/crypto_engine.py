from __future__ import annotations
from typing import Tuple
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

PBKDF2_ITERS = 200_000
KEY_LEN = 32
NONCE_LEN = 12

def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
    """Derive a 32‑byte key from a UTF‑8 password and 16‑byte salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """Return (nonce, ciphertext) using AES‑256‑GCM."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, data, associated_data=None)
    return nonce, ct


def decrypt_bytes(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def encrypt_file(path: str, key: bytes) -> str:
    """Encrypt a file in place by writing <name>.enc that contains nonce||ciphertext.
    Returns the path to the .enc file."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    with open(path, "rb") as f:
        data = f.read()
    nonce, ct = encrypt_bytes(data, key)
    out_path = path + ".enc"
    with open(out_path, "wb") as f:
        f.write(nonce + ct)
    return out_path


def decrypt_file(enc_path: str, key: bytes) -> str:
    """Decrypt a .enc file created by encrypt_file(). Writes back to original name.
    Returns the path to the restored plaintext file."""
    if not enc_path.endswith(".enc"):
        raise ValueError("Expected a .enc file")
    with open(enc_path, "rb") as f:
        blob = f.read()
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    pt = decrypt_bytes(nonce, ct, key)
    out_path = enc_path[:-4]
    with open(out_path, "wb") as f:
        f.write(pt)
    return out_path