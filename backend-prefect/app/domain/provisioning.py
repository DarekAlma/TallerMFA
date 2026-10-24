"""Process Manager del aprovisionamiento seguro de 2FA.

Coordina los pasos de larga duración (el usuario puede tardar minutos entre
generar el QR y escanearlo) y es el único lugar que cambia el estado de la
configuración, siempre pasando por la máquina de estados.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from app.config import settings
from app.core import totp
from app.core.security import encrypt_secret, generate_backup_codes, hash_backup_code
from app.domain.exceptions import MfaNotConfigured
from app.domain.models import MfaConfiguration, MfaStatus, User
from app.domain.state_machine import assert_transition
from app.infrastructure.repositories import UserRepository


@dataclass(frozen=True)
class ProvisioningTicket:
    secret: str
    otpauth_uri: str
    status: MfaStatus


class MfaProvisioningProcess:
    def __init__(self, repository: UserRepository):
        self._repository = repository

    def current_status(self, user_id: str) -> MfaStatus:
        config = self._repository.get_mfa_config(user_id)
        return config.status if config else MfaStatus.NOT_CONFIGURED

    def start(self, user: User) -> ProvisioningTicket:
        """Paso 1: genera la semilla y deja la configuración en PENDING_VERIFICATION."""
        assert_transition(self.current_status(user.id), MfaStatus.PENDING_VERIFICATION)
        secret = totp.generate_secret()
        self._repository.save_mfa_config(
            MfaConfiguration(
                user_id=user.id,
                secret_encrypted=encrypt_secret(secret),
                status=MfaStatus.PENDING_VERIFICATION,
            )
        )
        uri = totp.build_otpauth_uri(secret, user.username, settings.totp_issuer)
        return ProvisioningTicket(secret, uri, MfaStatus.PENDING_VERIFICATION)

    def complete(self, user_id: str) -> list[str]:
        """Paso 2: tras el primer código válido, PENDING_VERIFICATION -> ACTIVE.

        Devuelve los códigos de respaldo en claro (se muestran una única vez);
        en la base de datos solo se guarda su hash.
        """
        config = self._repository.get_mfa_config(user_id)
        if config is None:
            raise MfaNotConfigured("No hay aprovisionamiento 2FA en curso")
        assert_transition(config.status, MfaStatus.ACTIVE)
        config.status = MfaStatus.ACTIVE
        config.activated_at = datetime.now(timezone.utc)
        self._repository.save_mfa_config(config)

        codes = generate_backup_codes(settings.backup_codes_count)
        self._repository.replace_backup_codes(user_id, [hash_backup_code(c) for c in codes])
        return codes
