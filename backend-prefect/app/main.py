"""API FastAPI de Autenticación Escalonada (Step-Up) con observabilidad en Prefect.

Flujo:
  POST /auth/register          -> crea usuario (bcrypt) en Supabase
  POST /auth/login             -> flow login-password-step   -> pre_auth_token
  POST /auth/2fa/setup         -> flow mfa-provisioning-start  -> QR (PENDING_VERIFICATION)
  POST /auth/2fa/activate      -> flow mfa-provisioning-activate -> ACTIVE + access_token
  POST /auth/verify-2fa        -> flow verify-2fa-step-up       -> access_token (mfa_verified)
  GET  /api/boveda-secreta     -> ruta protegida (solo access_token con mfa_verified=true)
"""
from __future__ import annotations

from app.config import settings  # noqa: I001  (debe cargarse antes que Prefect)

import os
from datetime import datetime, timezone
from typing import Literal

import jwt
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, SecretStr

from app.core import tokens
from app.core.security import hash_password
from app.domain.exceptions import AuthError, InvalidAccessToken, InvalidPreAuthToken
from app.flows.auth_flows import activate_2fa_flow, login_flow, setup_2fa_flow, verify_2fa_flow
from app.infrastructure.repositories import get_repository

app = FastAPI(
    title="TallerMFA – Step-Up Auth + TOTP + Prefect",
    version="1.0.0",
    description="Backend de laboratorio: 2FA TOTP desde cero con observabilidad en Prefect.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def allow_private_network(request: Request, call_next):
    # Permite que la web desplegada en Vercel (origen público) llame a este
    # backend en localhost (Private/Local Network Access de Chrome).
    response = await call_next(request)
    if request.headers.get("access-control-request-private-network") == "true":
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


@app.exception_handler(AuthError)
async def auth_error_handler(_: Request, exc: AuthError):
    return JSONResponse(
        status_code=exc.status_code, content={"error": exc.error, "detail": exc.message}
    )


bearer = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Esquemas
# ---------------------------------------------------------------------------
class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[A-Za-z0-9_.\-]+$")
    password: SecretStr = Field(min_length=8, max_length=128)


class CodeBody(BaseModel):
    code: SecretStr = Field(min_length=6, max_length=20)
    method: Literal["totp", "backup"] = "totp"
    pre_auth_token: SecretStr | None = None  # alternativa al header Authorization


class ActivateBody(BaseModel):
    code: SecretStr = Field(min_length=6, max_length=6)
    pre_auth_token: SecretStr | None = None


def _pre_auth_from(
    credentials: HTTPAuthorizationCredentials | None, body_token: SecretStr | None = None
) -> SecretStr:
    if credentials:
        return SecretStr(credentials.credentials)
    if body_token:
        return body_token
    raise InvalidPreAuthToken("Falta el pre_auth_token (Authorization: Bearer <token>)")


def require_mfa_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> dict:
    """Dependencia de rutas protegidas: exige access_token con mfa_verified=true.

    Un pre_auth_token es rechazado aquí porque su audiencia es distinta.
    """
    if not credentials:
        raise InvalidAccessToken("Falta el access_token")
    try:
        claims = tokens.decode_token(credentials.credentials, tokens.ACCESS_AUDIENCE, "access")
    except jwt.InvalidTokenError:
        raise InvalidAccessToken("access_token inválido o expirado") from None
    if claims.get("mfa_verified") is not True:
        raise InvalidAccessToken("Se requiere sesión verificada con 2FA")
    return claims


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    # Abrir la URL del túnel ngrok en el navegador lleva a la documentación de la API.
    return RedirectResponse("/docs")


@app.get("/health")
def health():
    backend = "supabase" if settings.supabase_url else "sqlite"
    return {"status": "ok", "database": backend, "prefect_api": os.environ["PREFECT_API_URL"]}


@app.post("/auth/register", status_code=201)
def register(body: Credentials):
    user = get_repository().create_user(
        body.username.strip().lower(), hash_password(body.password.get_secret_value())
    )
    return {"id": user.id, "username": user.username, "mfa_status": "NOT_CONFIGURED"}


@app.post("/auth/login")
def login(body: Credentials):
    result = login_flow(username=body.username, password=body.password)
    return {"token_type": "bearer", "scope": "pre_auth", **result}


@app.post("/auth/2fa/setup")
def setup_2fa(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    return setup_2fa_flow(pre_auth_token=_pre_auth_from(credentials))


@app.post("/auth/2fa/activate")
def activate_2fa(
    body: ActivateBody, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)
):
    result = activate_2fa_flow(
        pre_auth_token=_pre_auth_from(credentials, body.pre_auth_token), code=body.code
    )
    return {"token_type": "bearer", **result}


@app.post("/auth/verify-2fa")
def verify_2fa(body: CodeBody, credentials: HTTPAuthorizationCredentials | None = Depends(bearer)):
    result = verify_2fa_flow(
        pre_auth_token=_pre_auth_from(credentials, body.pre_auth_token),
        code=body.code,
        method=body.method,
    )
    return {"token_type": "bearer", **result}


@app.get("/api/boveda-secreta")
def boveda_secreta(claims: dict = Depends(require_mfa_session)):
    return {
        "mensaje": f"Bienvenido a la bóveda, {claims['username']} 🔐",
        "secreto": "La respuesta es 42. Solo visible con mfa_verified=true.",
        "mfa_verified": claims["mfa_verified"],
        "amr": claims.get("amr"),
        "token_expira": datetime.fromtimestamp(claims["exp"], timezone.utc).isoformat(),
    }
