"""Primitivas de seguridad: hash de contraseñas, cifrado de secretos y códigos de respaldo."""
from __future__ import annotations

import base64
import hashlib
import secrets

import bcrypt
from cryptography.fernet import Fernet

from app.config import settings


# --- Contraseñas -----------------------------------------------------------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


# --- Cifrado en reposo de la semilla TOTP ----------------------------------
def _fernet() -> Fernet:
    if settings.secret_encryption_key:
        return Fernet(settings.secret_encryption_key.encode())
    derived = hashlib.sha256(("totp-seed:" + settings.jwt_secret).encode()).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


# --- Códigos de respaldo (un solo uso) -------------------------------------
_BACKUP_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sin 0/O/1/I para evitar confusiones


def generate_backup_codes(count: int) -> list[str]:
    codes = []
    for _ in range(count):
        raw = "".join(secrets.choice(_BACKUP_ALPHABET) for _ in range(8))
        codes.append(f"{raw[:4]}-{raw[4:]}")
    return codes


def normalize_backup_code(code: str) -> str:
    return code.strip().upper().replace("-", "").replace(" ", "")


def hash_backup_code(code: str) -> str:
    # Alta entropía (32^8) => SHA-256 es suficiente y permite búsqueda por igualdad.
    return hashlib.sha256(normalize_backup_code(code).encode()).hexdigest()


def mask(value: str, visible: int = 2) -> str:
    """Enmascara valores sensibles antes de enviarlos a los logs de Prefect."""
    if len(value) <= visible:
        return "*" * len(value)
    return value[:visible] + "*" * (len(value) - visible)
