"""Máquina de estados de la configuración 2FA.

    NOT_CONFIGURED ──setup──▶ PENDING_VERIFICATION ──primer código válido──▶ ACTIVE
                                   │  ▲
                                   └──┘ setup de nuevo (regenera el QR)

Mientras el estado sea PENDING_VERIFICATION el login NO exige 2FA, así un
usuario que generó el QR pero nunca lo escaneó no queda bloqueado.
"""
from __future__ import annotations

from app.domain.exceptions import InvalidStateTransition
from app.domain.models import MfaStatus

ALLOWED_TRANSITIONS: dict[MfaStatus, set[MfaStatus]] = {
    MfaStatus.NOT_CONFIGURED: {MfaStatus.PENDING_VERIFICATION},
    MfaStatus.PENDING_VERIFICATION: {MfaStatus.PENDING_VERIFICATION, MfaStatus.ACTIVE},
    MfaStatus.ACTIVE: set(),  # una vez activo no se re-aprovisiona con solo la contraseña
}


def assert_transition(current: MfaStatus, target: MfaStatus) -> None:
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidStateTransition(
            f"Transición no permitida: {current.value} -> {target.value}"
        )
