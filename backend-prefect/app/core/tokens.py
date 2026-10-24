"""Emisión y validación de JWT (Step-Up Authentication).

Se separan dos tipos de token con audiencias distintas para que uno NUNCA
pueda usarse en lugar del otro:

* pre_auth_token -> aud="mfa-verification", scope="pre_auth", mfa_verified=false.
  Solo sirve para /auth/verify-2fa y el aprovisionamiento (/auth/2fa/*).
* access_token   -> aud="api", scope="access", mfa_verified=true.
  Es el único aceptado por las rutas protegidas (/api/*).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass

import jwt

from app.config import settings

ALGORITHM = "HS256"
PRE_AUTH_AUDIENCE = "mfa-verification"
ACCESS_AUDIENCE = "api"


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_in: int


def issue_pre_auth_token(user_id: str, username: str, mfa_status: str) -> IssuedToken:
    jti = uuid.uuid4().hex
    now = int(time.time())
    payload = {
        "iss": settings.jwt_issuer,
        "aud": PRE_AUTH_AUDIENCE,
        "sub": user_id,
        "username": username,
        "scope": "pre_auth",
        "mfa_verified": False,
        "mfa_status": mfa_status,
        "jti": jti,
        "iat": now,
        "exp": now + settings.pre_auth_ttl_seconds,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)
    return IssuedToken(token, jti, settings.pre_auth_ttl_seconds)


def issue_access_token(user_id: str, username: str, method: str) -> IssuedToken:
    jti = uuid.uuid4().hex
    now = int(time.time())
    payload = {
        "iss": settings.jwt_issuer,
        "aud": ACCESS_AUDIENCE,
        "sub": user_id,
        "username": username,
        "scope": "access",
        "mfa_verified": True,
        "amr": ["pwd", "otp" if method == "totp" else "backup_code"],
        "jti": jti,
        "iat": now,
        "exp": now + settings.access_ttl_seconds,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)
    return IssuedToken(token, jti, settings.access_ttl_seconds)


def decode_token(token: str, audience: str, scope: str) -> dict:
    """Lanza jwt.InvalidTokenError si la firma, expiración, audiencia o scope no cuadran."""
    claims = jwt.decode(
        token,
        settings.jwt_secret,
        algorithms=[ALGORITHM],
        audience=audience,
        issuer=settings.jwt_issuer,
        options={"require": ["exp", "sub", "jti", "aud", "iss"]},
    )
    if claims.get("scope") != scope:
        raise jwt.InvalidTokenError("scope inválido")
    return claims
