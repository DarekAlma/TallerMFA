from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class MfaStatus(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"
    ACTIVE = "ACTIVE"


@dataclass
class User:
    id: str
    username: str
    password_hash: str


@dataclass
class MfaConfiguration:
    user_id: str
    secret_encrypted: str
    status: MfaStatus
    activated_at: datetime | None = None
