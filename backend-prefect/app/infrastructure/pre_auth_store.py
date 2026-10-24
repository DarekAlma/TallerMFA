"""Estado intermedio de autenticación (entre contraseña y segundo factor).

El JWT pre_auth por sí solo es stateless; este store le añade estado del lado
del servidor para poder: (1) limitar intentos fallidos de 2FA y (2) invalidar el
pre_auth_token apenas se emite el access_token (un solo uso).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass
class PreAuthSession:
    user_id: str
    expires_at: float
    failed_attempts: int = 0
    consumed: bool = False


class PreAuthStore:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._sessions: dict[str, PreAuthSession] = {}
        self._lock = threading.Lock()

    def open(self, jti: str, user_id: str, ttl_seconds: int) -> None:
        with self._lock:
            now = self._clock()
            for key in [k for k, s in self._sessions.items() if s.expires_at <= now]:
                del self._sessions[key]
            self._sessions[jti] = PreAuthSession(user_id, now + ttl_seconds)

    def get_active(self, jti: str) -> PreAuthSession | None:
        with self._lock:
            session = self._sessions.get(jti)
            if not session or session.consumed or session.expires_at <= self._clock():
                return None
            return session

    def register_failure(self, jti: str) -> int:
        with self._lock:
            session = self._sessions.get(jti)
            if not session:
                return 0
            session.failed_attempts += 1
            return session.failed_attempts

    def consume(self, jti: str) -> None:
        with self._lock:
            if jti in self._sessions:
                self._sessions[jti].consumed = True

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()


pre_auth_store = PreAuthStore()
