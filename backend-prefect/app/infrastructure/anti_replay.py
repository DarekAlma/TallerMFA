"""Caché Anti-Replay en memoria (dict + lock).

Guarda los pares (user_id, código) ya utilizados durante 90 s, que cubren las
tres ventanas aceptadas (C-1, C, C+1 = 3 × 30 s). Así un código válido no puede
usarse dos veces mientras siga siendo matemáticamente válido.
"""
from __future__ import annotations

import threading
import time

from app.config import settings


class AntiReplayCache:
    def __init__(self, ttl_seconds: int, clock=time.monotonic):
        self._ttl = ttl_seconds
        self._clock = clock
        self._used: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        expired = [key for key, expires_at in self._used.items() if expires_at <= now]
        for key in expired:
            del self._used[key]

    def was_used(self, user_id: str, code: str) -> bool:
        with self._lock:
            now = self._clock()
            self._purge(now)
            return (user_id, code) in self._used

    def mark_used(self, user_id: str, code: str) -> bool:
        """Registra el uso de forma atómica. Devuelve False si otro request ganó la carrera."""
        with self._lock:
            now = self._clock()
            self._purge(now)
            key = (user_id, code)
            if key in self._used:
                return False
            self._used[key] = now + self._ttl
            return True

    def seconds_left(self, user_id: str, code: str) -> int:
        with self._lock:
            expires_at = self._used.get((user_id, code))
            return max(0, int(expires_at - self._clock())) if expires_at else 0

    def clear(self) -> None:
        with self._lock:
            self._used.clear()


anti_replay_cache = AntiReplayCache(settings.anti_replay_ttl_seconds)
