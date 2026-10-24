"""Tareas observables de Prefect (@task).

Las 4 tareas del pipeline de verificación exigidas por la guía:
  1. validate_pre_auth_state
  2. check_anti_replay_cache
  3. execute_mfa_strategy
  4. issue_elevated_session
y las tareas auxiliares de login y aprovisionamiento.

`cache_policy=NO_CACHE`: cada intento debe evaluarse de nuevo, nunca reutilizar
un resultado previo (sería un bypass del segundo factor).
"""
from __future__ import annotations

import base64
import io

import jwt
import qrcode
from prefect import get_run_logger, task
from prefect.cache_policies import NO_CACHE
from prefect.runtime import flow_run
from pydantic import SecretStr

from app.config import settings
from app.core import tokens
from app.core.security import hash_password, mask, normalize_backup_code, verify_password
from app.domain.exceptions import (
    InvalidCredentials,
    InvalidPreAuthToken,
    InvalidSecondFactor,
    MfaNotConfigured,
    ReplayAttackDetected,
    TooManyAttempts,
)
from app.domain.models import MfaStatus
from app.domain.provisioning import MfaProvisioningProcess
from app.domain.strategies import resolve_strategy
from app.infrastructure.anti_replay import anti_replay_cache
from app.infrastructure.pre_auth_store import pre_auth_store
from app.infrastructure.repositories import get_repository

TASK_OPTS = dict(cache_policy=NO_CACHE, retries=0)

# Hash bcrypt de relleno: si el usuario no existe igual se ejecuta checkpw para
# que el tiempo de respuesta no revele qué usuarios existen.
_DUMMY_HASH = hash_password("timing-attack-padding")


def _audit(user_id: str | None, event: str, detail: str) -> None:
    try:
        get_repository().log_event(user_id, event, detail, str(flow_run.id or ""))
    except Exception as exc:  # la auditoría nunca debe tumbar el flujo
        get_run_logger().warning(f"No se pudo escribir auditoría: {exc}")


def replay_key(method: str, code: str) -> str:
    return f"backup:{normalize_backup_code(code)}" if method == "backup" else code.strip()


# ---------------------------------------------------------------------------
# Login (factor 1)
# ---------------------------------------------------------------------------
@task(name="authenticate_credentials", **TASK_OPTS)
def authenticate_credentials(username: str, password: SecretStr) -> dict:
    logger = get_run_logger()
    user = get_repository().get_user_by_username(username.strip().lower())
    ok = verify_password(password.get_secret_value(), user.password_hash if user else _DUMMY_HASH)
    if not user or not ok:
        logger.warning(f"Credenciales inválidas para '{username}'")
        _audit(user.id if user else None, "LOGIN_FAILED", f"username={username}")
        raise InvalidCredentials("Usuario o contraseña incorrectos")
    logger.info(f"Factor 1 (contraseña) correcto para '{user.username}' (id={user.id})")
    return {"user_id": user.id, "username": user.username}


@task(name="resolve_mfa_status", **TASK_OPTS)
def resolve_mfa_status(user_id: str) -> str:
    status = MfaProvisioningProcess(get_repository()).current_status(user_id)
    get_run_logger().info(f"Estado de la configuración 2FA: {status.value}")
    return status.value


@task(name="issue_pre_auth_token", **TASK_OPTS)
def issue_pre_auth_token(user_id: str, username: str, mfa_status: str) -> dict:
    issued = tokens.issue_pre_auth_token(user_id, username, mfa_status)
    pre_auth_store.open(issued.jti, user_id, issued.expires_in)
    next_step = "VERIFY_2FA" if mfa_status == MfaStatus.ACTIVE.value else "SETUP_2FA"
    get_run_logger().info(
        f"pre_auth_token emitido (jti={issued.jti[:8]}…, scope=pre_auth, "
        f"ttl={issued.expires_in}s). Siguiente paso: {next_step}"
    )
    _audit(user_id, "PRE_AUTH_ISSUED", f"next_step={next_step}")
    return {
        "pre_auth_token": issued.token,
        "expires_in": issued.expires_in,
        "mfa_status": mfa_status,
        "next_step": next_step,
    }


# ---------------------------------------------------------------------------
# Pipeline de verificación (factor 2)
# ---------------------------------------------------------------------------
@task(name="validate_pre_auth_state", **TASK_OPTS)
def validate_pre_auth_state(pre_auth_token: SecretStr) -> dict:
    """Task 1: el usuario debe venir con un token temporal válido y vigente."""
    logger = get_run_logger()
    try:
        claims = tokens.decode_token(
            pre_auth_token.get_secret_value(), tokens.PRE_AUTH_AUDIENCE, "pre_auth"
        )
    except jwt.ExpiredSignatureError:
        logger.error("pre_auth_token expirado")
        raise InvalidPreAuthToken("El token temporal expiró; inicia sesión de nuevo") from None
    except jwt.InvalidTokenError as exc:
        logger.error(f"pre_auth_token inválido: {exc}")
        raise InvalidPreAuthToken("Token temporal inválido") from None

    session = pre_auth_store.get_active(claims["jti"])
    if session is None or session.user_id != claims["sub"]:
        logger.error("pre_auth_token ya consumido, revocado o desconocido por el servidor")
        raise InvalidPreAuthToken("El token temporal ya fue usado o fue revocado")

    user = get_repository().get_user_by_id(claims["sub"])
    if user is None:
        raise InvalidPreAuthToken("Usuario inexistente")

    logger.info(
        f"Estado pre-auth válido: user='{user.username}', jti={claims['jti'][:8]}…, "
        f"intentos fallidos={session.failed_attempts}/{settings.max_mfa_attempts}"
    )
    return {"user_id": user.id, "username": user.username, "jti": claims["jti"]}


@task(name="check_anti_replay_cache", **TASK_OPTS)
def check_anti_replay_cache(user_id: str, code_key: str) -> bool:
    """Task 2: ¿la combinación (user_id, código) ya se usó en los últimos 90 s?"""
    logger = get_run_logger()
    if anti_replay_cache.was_used(user_id, code_key):
        left = anti_replay_cache.seconds_left(user_id, code_key)
        logger.error(
            f"REPLAY ATTACK: el código {mask(code_key)} ya fue usado por este usuario "
            f"(bloqueado {left}s más)"
        )
        _audit(user_id, "REPLAY_ATTACK_DETECTED", f"code={mask(code_key)}")
        raise ReplayAttackDetected("Este código ya fue utilizado. Espera el siguiente.")
    logger.info(f"Código {mask(code_key)} no registrado en la caché anti-replay")
    return True


@task(name="execute_mfa_strategy", **TASK_OPTS)
def execute_mfa_strategy(
    ctx: dict, code: SecretStr, method: str, required_status: str
) -> dict:
    """Task 3: ejecuta la estrategia (TOTPStrategy o BackupCodeStrategy)."""
    logger = get_run_logger()
    repository = get_repository()
    config = repository.get_mfa_config(ctx["user_id"])
    if config is None or config.status.value != required_status:
        current = config.status.value if config else MfaStatus.NOT_CONFIGURED.value
        logger.error(f"Estado 2FA {current}; se requería {required_status}")
        raise MfaNotConfigured(f"La 2FA está en estado {current}; se requería {required_status}")
    if method == "backup" and required_status != MfaStatus.ACTIVE.value:
        raise MfaNotConfigured("Los códigos de respaldo solo existen con la 2FA ACTIVE")

    strategy = resolve_strategy(method, repository)
    logger.info(f"Estrategia seleccionada: {type(strategy).__name__}")
    result = strategy.verify(config, code.get_secret_value())

    if not result.valid:
        attempts = pre_auth_store.register_failure(ctx["jti"])
        remaining = settings.max_mfa_attempts - attempts
        logger.error(f"Segundo factor inválido ({result.detail}). Intentos restantes: {remaining}")
        _audit(ctx["user_id"], "MFA_FAILED", f"method={method}; {result.detail}")
        if remaining <= 0:
            pre_auth_store.consume(ctx["jti"])
            raise TooManyAttempts("Demasiados intentos fallidos; inicia sesión de nuevo")
        raise InvalidSecondFactor(f"Código incorrecto. Intentos restantes: {remaining}")

    if result.matched_window:
        hints = {
            "C-1": "el reloj del celular va ATRASADO ~30 s",
            "C": "reloj sincronizado",
            "C+1": "el reloj del celular va ADELANTADO ~30 s",
        }
        logger.info(
            f"OK TOTP válido. Ventana que hizo match: {result.matched_window} "
            f"-> {hints[result.matched_window]} ({result.detail})"
        )
    else:
        logger.info(f"OK {result.detail}")
    return {"method": result.method, "matched_window": result.matched_window}


@task(name="issue_elevated_session", **TASK_OPTS)
def issue_elevated_session(ctx: dict, code_key: str, method: str) -> dict:
    """Task 4: marca el código como usado y emite el JWT final con mfa_verified=true."""
    logger = get_run_logger()
    # mark_used es atómico: si dos peticiones con el mismo código llegaron a la vez,
    # solo una gana; la otra se trata como replay.
    if not anti_replay_cache.mark_used(ctx["user_id"], code_key):
        logger.error("REPLAY ATTACK (carrera): el código se usó en paralelo")
        raise ReplayAttackDetected("Este código ya fue utilizado. Espera el siguiente.")
    pre_auth_store.consume(ctx["jti"])  # el pre_auth_token es de un solo uso
    issued = tokens.issue_access_token(ctx["user_id"], ctx["username"], method)
    logger.info(
        f"Código {mask(code_key)} marcado como usado ({settings.anti_replay_ttl_seconds}s). "
        f"access_token emitido con mfa_verified=true (ttl={issued.expires_in}s); "
        f"pre_auth_token {ctx['jti'][:8]}… invalidado"
    )
    _audit(ctx["user_id"], "MFA_VERIFIED", f"method={method}")
    return {"access_token": issued.token, "expires_in": issued.expires_in}


# ---------------------------------------------------------------------------
# Aprovisionamiento (Process Manager)
# ---------------------------------------------------------------------------
@task(name="start_mfa_provisioning", **TASK_OPTS)
def start_mfa_provisioning(ctx: dict) -> dict:
    repository = get_repository()
    user = repository.get_user_by_id(ctx["user_id"])
    ticket = MfaProvisioningProcess(repository).start(user)
    get_run_logger().info(
        f"Semilla TOTP generada y cifrada. Estado -> {ticket.status.value}"
    )
    _audit(ctx["user_id"], "MFA_PENDING_VERIFICATION", "semilla generada")
    return {"secret": ticket.secret, "otpauth_uri": ticket.otpauth_uri, "status": ticket.status.value}


@task(name="render_provisioning_qr", **TASK_OPTS)
def render_provisioning_qr(otpauth_uri: str) -> str:
    image = qrcode.make(otpauth_uri, box_size=8, border=2)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    get_run_logger().info("QR otpauth:// generado")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()


@task(name="activate_mfa_configuration", **TASK_OPTS)
def activate_mfa_configuration(ctx: dict) -> list[str]:
    codes = MfaProvisioningProcess(get_repository()).complete(ctx["user_id"])
    get_run_logger().info(
        f"Estado -> ACTIVE. {len(codes)} códigos de respaldo generados (solo se guarda su hash)"
    )
    _audit(ctx["user_id"], "MFA_ACTIVE", f"backup_codes={len(codes)}")
    return codes
