"""Strategy Pattern para el segundo factor.

`SecondFactorStrategy` define el contrato; `TOTPStrategy` y `BackupCodeStrategy`
son intercambiables y se eligen en tiempo de ejecución con `resolve_strategy`.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.core import totp
from app.core.security import decrypt_secret, hash_backup_code
from app.domain.models import MfaConfiguration
from app.infrastructure.repositories import UserRepository


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    method: str
    matched_window: str | None = None  # "C-1" | "C" | "C+1" (solo TOTP)
    detail: str = ""


class SecondFactorStrategy(ABC):
    method: str

    @abstractmethod
    def verify(self, config: MfaConfiguration, code: str) -> VerificationResult: ...


class TOTPStrategy(SecondFactorStrategy):
    method = "totp"

    def __init__(self, clock=time.time):
        self._clock = clock

    def verify(self, config: MfaConfiguration, code: str) -> VerificationResult:
        code = code.strip()
        if len(code) != totp.DIGITS or not code.isdigit():
            return VerificationResult(False, self.method, detail="formato inválido (6 dígitos)")
        secret = decrypt_secret(config.secret_encrypted)
        now = self._clock()
        delta = totp.match_window(secret, code, now)
        if delta is None:
            return VerificationResult(
                False, self.method, detail=f"sin match en C-1/C/C+1 (C={totp.counter_at(now)})"
            )
        return VerificationResult(
            True,
            self.method,
            matched_window=totp.WINDOWS[delta],
            detail=f"C={totp.counter_at(now)}, match en contador {totp.counter_at(now) + delta}",
        )


class BackupCodeStrategy(SecondFactorStrategy):
    method = "backup"

    def __init__(self, repository: UserRepository):
        self._repository = repository

    def verify(self, config: MfaConfiguration, code: str) -> VerificationResult:
        # consume_backup_code es atómico: marca used_at solo si estaba sin usar.
        consumed = self._repository.consume_backup_code(config.user_id, hash_backup_code(code))
        if not consumed:
            return VerificationResult(False, self.method, detail="código inexistente o ya usado")
        remaining = self._repository.count_unused_backup_codes(config.user_id)
        return VerificationResult(
            True, self.method, detail=f"código de respaldo consumido; quedan {remaining}"
        )


def resolve_strategy(method: str, repository: UserRepository) -> SecondFactorStrategy:
    strategies: dict[str, SecondFactorStrategy] = {
        TOTPStrategy.method: TOTPStrategy(),
        BackupCodeStrategy.method: BackupCodeStrategy(repository),
    }
    try:
        return strategies[method]
    except KeyError:
        raise ValueError(f"Método de segundo factor no soportado: {method}") from None
