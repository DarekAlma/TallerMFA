"""Pruebas de aceptación de la guía, automatizadas sobre la API real + Prefect."""
import uuid
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.core import totp
from app.main import app

client = TestClient(app)
PASSWORD = "SuperSecreta123"


def _register_and_login():
    username = f"user_{uuid.uuid4().hex[:8]}"
    assert client.post("/auth/register", json={"username": username, "password": PASSWORD}).status_code == 201
    r = client.post("/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return username, r.json()


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _enrolled_user():
    """Usuario con 2FA ACTIVE. Devuelve (username, secret, backup_codes, codigo_usado)."""
    username, login = _register_and_login()
    pre = login["pre_auth_token"]
    setup = client.post("/auth/2fa/setup", headers=_auth(pre)).json()
    secret = parse_qs(urlparse(setup["otpauth_uri"]).query)["secret"][0]
    code = totp.totp(secret)
    activated = client.post("/auth/2fa/activate", headers=_auth(pre), json={"code": code})
    assert activated.status_code == 200, activated.text
    return username, secret, activated.json()["backup_codes"], code


def test_login_returns_restricted_pre_auth_token():
    _, login = _register_and_login()
    assert login["scope"] == "pre_auth"
    assert login["next_step"] == "SETUP_2FA"
    # El pre_auth_token NO abre la bóveda (Step-Up)
    r = client.get("/api/boveda-secreta", headers=_auth(login["pre_auth_token"]))
    assert r.status_code == 401


def test_wrong_password():
    username, _ = _register_and_login()
    r = client.post("/auth/login", json={"username": username, "password": "incorrecta123"})
    assert r.status_code == 401
    assert r.json()["error"] == "INVALID_CREDENTIALS"


def test_provisioning_state_machine():
    _, login = _register_and_login()
    pre = login["pre_auth_token"]
    setup = client.post("/auth/2fa/setup", headers=_auth(pre))
    assert setup.status_code == 200
    body = setup.json()
    assert body["status"] == "PENDING_VERIFICATION"
    assert body["qr_png_base64"].startswith("data:image/png;base64,")

    # Un código erróneo NO activa
    bad = client.post("/auth/2fa/activate", headers=_auth(pre), json={"code": "000000"})
    assert bad.status_code == 401

    secret = parse_qs(urlparse(body["otpauth_uri"]).query)["secret"][0]
    ok = client.post("/auth/2fa/activate", headers=_auth(pre), json={"code": totp.totp(secret)})
    assert ok.status_code == 200
    data = ok.json()
    assert data["status"] == "ACTIVE" and data["mfa_verified"] is True
    assert len(data["backup_codes"]) == 8
    # Con ACTIVE ya no se puede re-aprovisionar solo con la contraseña
    assert client.post("/auth/2fa/setup", headers=_auth(pre)).status_code == 401  # pre_auth consumido


def test_pending_user_is_not_locked_out():
    username, login = _register_and_login()
    client.post("/auth/2fa/setup", headers=_auth(login["pre_auth_token"]))
    # Nunca escaneó el QR: el siguiente login sigue en SETUP_2FA (no queda bloqueado)
    again = client.post("/auth/login", json={"username": username, "password": PASSWORD}).json()
    assert again["mfa_status"] == "PENDING_VERIFICATION"
    assert again["next_step"] == "SETUP_2FA"


def test_full_step_up_and_vault():
    username, secret, _, used_code = _enrolled_user()
    login = client.post("/auth/login", json={"username": username, "password": PASSWORD}).json()
    assert login["next_step"] == "VERIFY_2FA"
    # El código usado en la activación sigue vetado por anti-replay; usamos la ventana C+1
    code = totp.hotp(totp.base32_decode(secret), totp.counter_at() + 1)
    r = client.post("/auth/verify-2fa", headers=_auth(login["pre_auth_token"]), json={"code": code})
    assert r.status_code == 200, r.text
    assert r.json()["matched_window"] == "C+1"
    vault = client.get("/api/boveda-secreta", headers=_auth(r.json()["access_token"]))
    assert vault.status_code == 200
    assert vault.json()["mfa_verified"] is True


def test_replay_attack_is_blocked():
    username, secret, _, activation_code = _enrolled_user()
    login = client.post("/auth/login", json={"username": username, "password": PASSWORD}).json()
    r = client.post(
        "/auth/verify-2fa", headers=_auth(login["pre_auth_token"]), json={"code": activation_code}
    )
    assert r.status_code == 401
    assert r.json()["error"] == "REPLAY_ATTACK_DETECTED"


def test_backup_code_strategy_single_use():
    username, _, backup_codes, _ = _enrolled_user()
    login = client.post("/auth/login", json={"username": username, "password": PASSWORD}).json()
    r = client.post(
        "/auth/verify-2fa",
        headers=_auth(login["pre_auth_token"]),
        json={"code": backup_codes[0], "method": "backup"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["method"] == "backup"

    login2 = client.post("/auth/login", json={"username": username, "password": PASSWORD}).json()
    again = client.post(
        "/auth/verify-2fa",
        headers=_auth(login2["pre_auth_token"]),
        json={"code": backup_codes[0], "method": "backup"},
    )
    assert again.status_code == 401


def test_pre_auth_token_is_single_use():
    username, secret, _, _ = _enrolled_user()
    login = client.post("/auth/login", json={"username": username, "password": PASSWORD}).json()
    pre = login["pre_auth_token"]
    key = totp.base32_decode(secret)
    ok = client.post("/auth/verify-2fa", headers=_auth(pre), json={"code": totp.hotp(key, totp.counter_at() + 1)})
    assert ok.status_code == 200
    reuse = client.post("/auth/verify-2fa", headers=_auth(pre), json={"code": totp.hotp(key, totp.counter_at() - 1)})
    assert reuse.status_code == 401
    assert reuse.json()["error"] == "INVALID_PRE_AUTH_TOKEN"


def test_too_many_attempts():
    username, _, _, _ = _enrolled_user()
    pre = client.post("/auth/login", json={"username": username, "password": PASSWORD}).json()["pre_auth_token"]
    statuses = [
        client.post("/auth/verify-2fa", headers=_auth(pre), json={"code": f"{i:06d}"}).status_code
        for i in range(5)
    ]
    assert statuses[-1] == 429
