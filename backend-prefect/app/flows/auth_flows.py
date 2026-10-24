"""Flows de Prefect (@flow). Cada endpoint de autenticación invoca uno.

Los parámetros sensibles se reciben como `SecretStr`, así en la UI de Prefect
aparecen como '**********' y nunca se filtran contraseñas, tokens ni códigos.
"""
from __future__ import annotations

from prefect import flow
from pydantic import SecretStr

from app.domain.models import MfaStatus
from app.flows.tasks import (
    activate_mfa_configuration,
    authenticate_credentials,
    check_anti_replay_cache,
    execute_mfa_strategy,
    issue_elevated_session,
    issue_pre_auth_token,
    render_provisioning_qr,
    replay_key,
    resolve_mfa_status,
    start_mfa_provisioning,
    validate_pre_auth_state,
)


@flow(name="login-password-step", flow_run_name="login-{username}")
def login_flow(username: str, password: SecretStr) -> dict:
    """Factor 1: usuario + contraseña -> pre_auth_token (permisos restringidos)."""
    user = authenticate_credentials(username, password)
    mfa_status = resolve_mfa_status(user["user_id"])
    return issue_pre_auth_token(user["user_id"], user["username"], mfa_status)


@flow(name="verify-2fa-step-up", flow_run_name="verify-2fa-{method}")
def verify_2fa_flow(pre_auth_token: SecretStr, code: SecretStr, method: str = "totp") -> dict:
    """Factor 2 (Step-Up): pre_auth_token + código -> access_token con mfa_verified=true."""
    ctx = validate_pre_auth_state(pre_auth_token)
    key = replay_key(method, code.get_secret_value())
    check_anti_replay_cache(ctx["user_id"], key)
    result = execute_mfa_strategy(ctx, code, method, MfaStatus.ACTIVE.value)
    session = issue_elevated_session(ctx, key, method)
    return {**session, **result, "mfa_verified": True}


@flow(name="mfa-provisioning-start", flow_run_name="provisioning-start")
def setup_2fa_flow(pre_auth_token: SecretStr) -> dict:
    """Process Manager, paso 1: genera QR y deja la 2FA en PENDING_VERIFICATION."""
    ctx = validate_pre_auth_state(pre_auth_token)
    ticket = start_mfa_provisioning(ctx)
    qr = render_provisioning_qr(ticket["otpauth_uri"])
    return {**ticket, "qr_png_base64": qr}


@flow(name="mfa-provisioning-activate", flow_run_name="provisioning-activate")
def activate_2fa_flow(pre_auth_token: SecretStr, code: SecretStr) -> dict:
    """Process Manager, paso 2: primer código válido -> ACTIVE + sesión elevada."""
    ctx = validate_pre_auth_state(pre_auth_token)
    key = replay_key("totp", code.get_secret_value())
    check_anti_replay_cache(ctx["user_id"], key)
    result = execute_mfa_strategy(ctx, code, "totp", MfaStatus.PENDING_VERIFICATION.value)
    backup_codes = activate_mfa_configuration(ctx)
    session = issue_elevated_session(ctx, key, "totp")
    return {
        **session,
        **result,
        "mfa_verified": True,
        "status": MfaStatus.ACTIVE.value,
        "backup_codes": backup_codes,
    }
