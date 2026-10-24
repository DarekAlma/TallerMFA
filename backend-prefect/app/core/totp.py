"""TOTP (RFC 6238) implementado desde cero.

Solo se usan primitivas estándar de Python: `hmac` + `hashlib.sha1` para el
HMAC y `base64` para Base32. No se usan librerías TOTP (pyotp, etc.).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote, urlencode

TIME_STEP = 30
DIGITS = 6
# Ventanas evaluadas: C-1 (reloj del celular atrasado), C (exacto), C+1 (adelantado)
WINDOWS = {-1: "C-1", 0: "C", 1: "C+1"}


def generate_secret(num_bytes: int = 20) -> str:
    """Semilla aleatoria de 160 bits (recomendado para SHA-1) en Base32 sin padding."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def base32_decode(secret: str) -> bytes:
    normalized = secret.strip().replace(" ", "").replace("-", "").upper()
    normalized += "=" * (-len(normalized) % 8)
    return base64.b32decode(normalized, casefold=True)


def counter_at(timestamp: float | None = None) -> int:
    """C = floor(UnixTime / 30)."""
    if timestamp is None:
        timestamp = time.time()
    return int(timestamp // TIME_STEP)


def hotp(key: bytes, counter: int) -> str:
    # 1. Contador como entero de 8 bytes Big-Endian
    message = struct.pack(">Q", counter)
    # 2. HMAC-SHA1(K, C) -> 20 bytes
    digest = hmac.new(key, message, hashlib.sha1).digest()
    # 3. Truncamiento dinámico
    offset = digest[19] & 0x0F
    binary = (
        (digest[offset] & 0x7F) << 24
        | digest[offset + 1] << 16
        | digest[offset + 2] << 8
        | digest[offset + 3]
    )
    # 4. Módulo 10^6 y relleno con ceros
    return str(binary % 10**DIGITS).zfill(DIGITS)


def totp(secret: str, timestamp: float | None = None) -> str:
    return hotp(base32_decode(secret), counter_at(timestamp))


def match_window(secret: str, code: str, timestamp: float | None = None) -> int | None:
    """Devuelve el desplazamiento (-1, 0, +1) en el que hizo match el código, o None."""
    key = base32_decode(secret)
    current = counter_at(timestamp)
    for delta in WINDOWS:
        # compare_digest evita ataques de temporización
        if hmac.compare_digest(hotp(key, current + delta), code):
            return delta
    return None


def build_otpauth_uri(secret: str, account_name: str, issuer: str) -> str:
    label = quote(f"{issuer}:{account_name}")
    params = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": DIGITS,
            "period": TIME_STEP,
        }
    )
    return f"otpauth://totp/{label}?{params}"
