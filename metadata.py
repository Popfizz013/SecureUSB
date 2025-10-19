from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional
import base64
import hashlib
import json
import os
import time
import uuid as uuidlib
from .crypto_engine import derive_key, PBKDF2_ITERS, KEY_LEN

META_DIR = ".secureusb"
META_FILE = "meta.json"
VERIFIER_MSG = b"SecureUSB verifier v1"


@dataclass
class KDFParams:
    algo: str
    iters: int


@dataclass
class Meta:
    uuid: str
    owner_id: str
    salt_b64: str
    kdf: KDFParams
    created_at: str
    key_verifier_hex: str

    @staticmethod
    def path_for(mount_point: str) -> str:
        return os.path.join(mount_point, META_DIR, META_FILE)


def _ensure_meta_dir(mount_point: str) -> str:
    path = os.path.join(mount_point, META_DIR)
    os.makedirs(path, exist_ok=True)
    return path


def init_metadata(mount_point: str, owner_id: str, password: str) -> Meta:
    _ensure_meta_dir(mount_point)
    salt = os.urandom(16)
    key = derive_key(password, salt)
    # simple verifier = SHA256(key || VERIFIER_MSG)
    verifier = hashlib.sha256(key + VERIFIER_MSG).hexdigest()
    m = Meta(
        uuid=str(uuidlib.uuid4()),
        owner_id=owner_id,
        salt_b64=base64.b64encode(salt).decode("ascii"),
        kdf=KDFParams(algo="PBKDF2-HMAC-SHA256", iters=PBKDF2_ITERS),
        created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        key_verifier_hex=verifier,
    )
    with open(Meta.path_for(mount_point), "w", encoding="utf-8") as f:
        json.dump(asdict(m), f, indent=2)
    return m


def load_metadata(mount_point: str) -> Optional[Meta]:
    path = Meta.path_for(mount_point)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    kdf = KDFParams(**data["kdf"]) if isinstance(data.get("kdf"), dict) else KDFParams("PBKDF2-HMAC-SHA256", PBKDF2_ITERS)
    return Meta(
        uuid=data["uuid"],
        owner_id=data.get("owner_id", "unknown"),
        salt_b64=data["salt_b64"],
        kdf=kdf,
        created_at=data.get("created_at", ""),
        key_verifier_hex=data.get("key_verifier_hex", ""),
    )


def verify_password(mount_point: str, password: str) -> bool:
    meta = load_metadata(mount_point)
    if not meta:
        return False
    salt = base64.b64decode(meta.salt_b64)
    key = derive_key(password, salt, iterations=meta.kdf.iters)
    verifier = hashlib.sha256(key + VERIFIER_MSG).hexdigest()
    return verifier == meta.key_verifier_hex


def get_key_from_password(mount_point: str, password: str) -> bytes:
    meta = load_metadata(mount_point)
    if not meta:
        raise FileNotFoundError("Metadata not found; run 'init' first")
    salt = base64.b64decode(meta.salt_b64)
    return derive_key(password, salt, iterations=meta.kdf.iters)