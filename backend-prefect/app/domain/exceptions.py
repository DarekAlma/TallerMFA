"""Excepciones de dominio. Cada una lleva el código HTTP y un identificador estable
que la API devuelve al cliente y que se ve en los logs/estado de Prefect."""
from __future__ import annotations


class AuthError(Exception):
    status_code = 401
    error = "AUTH_ERROR"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class InvalidCredentials(AuthError):
    error = "INVALID_CREDENTIALS"


class UserAlreadyExists(AuthError):
    status_code = 409
    error = "USER_ALREADY_EXISTS"


class InvalidPreAuthToken(AuthError):
    error = "INVALID_PRE_AUTH_TOKEN"


class InvalidAccessToken(AuthError):
    error = "INVALID_ACCESS_TOKEN"


class ReplayAttackDetected(AuthError):
    """El par (user_id, código) ya se usó dentro de la ventana anti-replay."""

    error = "REPLAY_ATTACK_DETECTED"


class InvalidSecondFactor(AuthError):
    error = "INVALID_SECOND_FACTOR"


class TooManyAttempts(AuthError):
    status_code = 429
    error = "TOO_MANY_ATTEMPTS"


class MfaNotConfigured(AuthError):
    status_code = 409
    error = "MFA_NOT_CONFIGURED"


class InvalidStateTransition(AuthError):
    status_code = 409
    error = "INVALID_STATE_TRANSITION"
