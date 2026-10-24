"""Configuración centralizada (variables de entorno / archivo .env).

Este módulo se importa ANTES que Prefect para que PREFECT_API_URL quede
definido y los flows se reporten al servidor local (`prefect server start`).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

os.environ.setdefault("PREFECT_API_URL", "http://127.0.0.1:4200/api")


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    # JWT
    jwt_secret: str = os.getenv("JWT_SECRET", "dev-only-change-me-please-32-bytes-min!!")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "taller-mfa-backend")
    pre_auth_ttl_seconds: int = int(os.getenv("PRE_AUTH_TTL_SECONDS", "300"))
    access_ttl_seconds: int = int(os.getenv("ACCESS_TTL_SECONDS", "900"))
    max_mfa_attempts: int = int(os.getenv("MAX_MFA_ATTEMPTS", "5"))

    # TOTP
    totp_issuer: str = os.getenv("TOTP_ISSUER", "TallerMFA")
    anti_replay_ttl_seconds: int = int(os.getenv("ANTI_REPLAY_TTL_SECONDS", "90"))
    backup_codes_count: int = int(os.getenv("BACKUP_CODES_COUNT", "8"))

    # Cifrado del secreto TOTP en reposo (Fernet). Si está vacío se deriva de JWT_SECRET.
    secret_encryption_key: str = os.getenv("SECRET_ENCRYPTION_KEY", "")

    # Persistencia: si hay SUPABASE_URL se usa Supabase; si no, SQLite local.
    supabase_url: str = os.getenv("SUPABASE_URL", "").rstrip("/")
    supabase_service_key: str = os.getenv("SUPABASE_SERVICE_KEY", "")
    sqlite_path: str = os.getenv("SQLITE_PATH", str(BASE_DIR / "local.db"))

    # CORS (web en Vercel / localhost)
    cors_origins: list[str] = field(
        default_factory=lambda: _csv(os.getenv("CORS_ORIGINS", "*"))
    )


settings = Settings()
