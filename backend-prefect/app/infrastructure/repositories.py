"""Repository Pattern: el dominio y los flows solo conocen `UserRepository`.

* `SupabaseRepository`: Postgres de Supabase vía su API REST (PostgREST),
  autenticado con la llave secreta / service_role (ignora RLS, nunca va al cliente).
* `SQLiteRepository`: respaldo local para pruebas o si no hay Supabase configurado.
"""
from __future__ import annotations

import sqlite3
import threading
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from functools import lru_cache

import httpx

from app.config import settings
from app.domain.exceptions import UserAlreadyExists
from app.domain.models import MfaConfiguration, MfaStatus, User


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class UserRepository(ABC):
    @abstractmethod
    def create_user(self, username: str, password_hash: str) -> User: ...

    @abstractmethod
    def get_user_by_username(self, username: str) -> User | None: ...

    @abstractmethod
    def get_user_by_id(self, user_id: str) -> User | None: ...

    @abstractmethod
    def get_mfa_config(self, user_id: str) -> MfaConfiguration | None: ...

    @abstractmethod
    def save_mfa_config(self, config: MfaConfiguration) -> None: ...

    @abstractmethod
    def replace_backup_codes(self, user_id: str, code_hashes: list[str]) -> None: ...

    @abstractmethod
    def consume_backup_code(self, user_id: str, code_hash: str) -> bool: ...

    @abstractmethod
    def count_unused_backup_codes(self, user_id: str) -> int: ...

    @abstractmethod
    def log_event(
        self, user_id: str | None, event: str, detail: str, flow_run_id: str | None
    ) -> None: ...


# ---------------------------------------------------------------------------
# Supabase (PostgREST)
# ---------------------------------------------------------------------------
class SupabaseRepository(UserRepository):
    def __init__(self, url: str, service_key: str):
        headers = {"apikey": service_key, "Content-Type": "application/json"}
        # Las llaves legacy (service_role) son JWT y van también en Authorization.
        # Las nuevas llaves "sb_secret_..." solo van en el header apikey.
        if not service_key.startswith("sb_"):
            headers["Authorization"] = f"Bearer {service_key}"
        self._http = httpx.Client(base_url=f"{url}/rest/v1", headers=headers, timeout=10)

    def _check(self, response: httpx.Response) -> httpx.Response:
        if response.status_code >= 400:
            raise RuntimeError(f"Supabase {response.status_code}: {response.text}")
        return response

    @staticmethod
    def _user(row: dict) -> User:
        return User(id=row["id"], username=row["username"], password_hash=row["password_hash"])

    def create_user(self, username: str, password_hash: str) -> User:
        response = self._http.post(
            "/users",
            json={"username": username, "password_hash": password_hash},
            headers={"Prefer": "return=representation"},
        )
        if response.status_code == 409:
            raise UserAlreadyExists(f"El usuario '{username}' ya existe")
        return self._user(self._check(response).json()[0])

    def _get_user(self, column: str, value: str) -> User | None:
        rows = self._check(
            self._http.get("/users", params={column: f"eq.{value}", "select": "*"})
        ).json()
        return self._user(rows[0]) if rows else None

    def get_user_by_username(self, username: str) -> User | None:
        return self._get_user("username", username)

    def get_user_by_id(self, user_id: str) -> User | None:
        return self._get_user("id", user_id)

    def get_mfa_config(self, user_id: str) -> MfaConfiguration | None:
        rows = self._check(
            self._http.get(
                "/mfa_configurations", params={"user_id": f"eq.{user_id}", "select": "*"}
            )
        ).json()
        if not rows:
            return None
        row = rows[0]
        return MfaConfiguration(
            user_id=row["user_id"],
            secret_encrypted=row["secret_encrypted"],
            status=MfaStatus(row["status"]),
            activated_at=_parse_dt(row.get("activated_at")),
        )

    def save_mfa_config(self, config: MfaConfiguration) -> None:
        self._check(
            self._http.post(
                "/mfa_configurations",
                params={"on_conflict": "user_id"},
                json={
                    "user_id": config.user_id,
                    "secret_encrypted": config.secret_encrypted,
                    "status": config.status.value,
                    "activated_at": config.activated_at.isoformat() if config.activated_at else None,
                    "updated_at": _now_iso(),
                },
                headers={"Prefer": "resolution=merge-duplicates,return=minimal"},
            )
        )

    def replace_backup_codes(self, user_id: str, code_hashes: list[str]) -> None:
        self._check(self._http.delete("/backup_codes", params={"user_id": f"eq.{user_id}"}))
        self._check(
            self._http.post(
                "/backup_codes",
                json=[{"user_id": user_id, "code_hash": h} for h in code_hashes],
                headers={"Prefer": "return=minimal"},
            )
        )

    def consume_backup_code(self, user_id: str, code_hash: str) -> bool:
        # UPDATE ... WHERE used_at IS NULL es atómico en Postgres: dos peticiones
        # simultáneas con el mismo código no pueden consumirlo ambas.
        rows = self._check(
            self._http.patch(
                "/backup_codes",
                params={
                    "user_id": f"eq.{user_id}",
                    "code_hash": f"eq.{code_hash}",
                    "used_at": "is.null",
                },
                json={"used_at": _now_iso()},
                headers={"Prefer": "return=representation"},
            )
        ).json()
        return len(rows) > 0

    def count_unused_backup_codes(self, user_id: str) -> int:
        rows = self._check(
            self._http.get(
                "/backup_codes",
                params={"user_id": f"eq.{user_id}", "used_at": "is.null", "select": "id"},
            )
        ).json()
        return len(rows)

    def log_event(self, user_id, event, detail, flow_run_id) -> None:
        self._check(
            self._http.post(
                "/auth_audit_log",
                json={
                    "user_id": user_id,
                    "event": event,
                    "detail": detail,
                    "flow_run_id": flow_run_id,
                },
                headers={"Prefer": "return=minimal"},
            )
        )


# ---------------------------------------------------------------------------
# SQLite (respaldo local / tests)
# ---------------------------------------------------------------------------
class SQLiteRepository(UserRepository):
    def __init__(self, path: str):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mfa_configurations (
                    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    secret_encrypted TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('PENDING_VERIFICATION','ACTIVE')),
                    activated_at TEXT,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS backup_codes (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    code_hash TEXT NOT NULL,
                    used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS auth_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    event TEXT NOT NULL,
                    detail TEXT,
                    flow_run_id TEXT,
                    created_at TEXT NOT NULL
                );
                """
            )

    def _one(self, sql: str, params: tuple) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def create_user(self, username: str, password_hash: str) -> User:
        user = User(id=str(uuid.uuid4()), username=username, password_hash=password_hash)
        try:
            with self._lock, self._conn:
                self._conn.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?)",
                    (user.id, username, password_hash, _now_iso()),
                )
        except sqlite3.IntegrityError:
            raise UserAlreadyExists(f"El usuario '{username}' ya existe") from None
        return user

    def get_user_by_username(self, username: str) -> User | None:
        row = self._one("SELECT * FROM users WHERE username = ?", (username,))
        return User(row["id"], row["username"], row["password_hash"]) if row else None

    def get_user_by_id(self, user_id: str) -> User | None:
        row = self._one("SELECT * FROM users WHERE id = ?", (user_id,))
        return User(row["id"], row["username"], row["password_hash"]) if row else None

    def get_mfa_config(self, user_id: str) -> MfaConfiguration | None:
        row = self._one("SELECT * FROM mfa_configurations WHERE user_id = ?", (user_id,))
        if not row:
            return None
        return MfaConfiguration(
            user_id=row["user_id"],
            secret_encrypted=row["secret_encrypted"],
            status=MfaStatus(row["status"]),
            activated_at=_parse_dt(row["activated_at"]),
        )

    def save_mfa_config(self, config: MfaConfiguration) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                """
                INSERT INTO mfa_configurations (user_id, secret_encrypted, status, activated_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    secret_encrypted = excluded.secret_encrypted,
                    status = excluded.status,
                    activated_at = excluded.activated_at,
                    updated_at = excluded.updated_at
                """,
                (
                    config.user_id,
                    config.secret_encrypted,
                    config.status.value,
                    config.activated_at.isoformat() if config.activated_at else None,
                    _now_iso(),
                ),
            )

    def replace_backup_codes(self, user_id: str, code_hashes: list[str]) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
            self._conn.executemany(
                "INSERT INTO backup_codes (id, user_id, code_hash) VALUES (?, ?, ?)",
                [(str(uuid.uuid4()), user_id, h) for h in code_hashes],
            )

    def consume_backup_code(self, user_id: str, code_hash: str) -> bool:
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "UPDATE backup_codes SET used_at = ? "
                "WHERE user_id = ? AND code_hash = ? AND used_at IS NULL",
                (_now_iso(), user_id, code_hash),
            )
            return cursor.rowcount > 0

    def count_unused_backup_codes(self, user_id: str) -> int:
        row = self._one(
            "SELECT COUNT(*) AS n FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
            (user_id,),
        )
        return int(row["n"])

    def log_event(self, user_id, event, detail, flow_run_id) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO auth_audit_log (user_id, event, detail, flow_run_id, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (user_id, event, detail, flow_run_id, _now_iso()),
            )


@lru_cache
def get_repository() -> UserRepository:
    if settings.supabase_url and settings.supabase_service_key:
        return SupabaseRepository(settings.supabase_url, settings.supabase_service_key)
    return SQLiteRepository(settings.sqlite_path)
