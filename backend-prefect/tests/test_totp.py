"""Vectores oficiales del RFC 6238 (Apéndice B, SHA-1) y RFC 4226 (Apéndice D)."""
import base64

import pytest

from app.core import totp

RFC_SECRET_ASCII = b"12345678901234567890"
RFC_SECRET_B32 = base64.b32encode(RFC_SECRET_ASCII).decode()


@pytest.mark.parametrize(
    "counter,expected",
    [(0, "755224"), (1, "287082"), (2, "359152"), (3, "969429"), (9, "520489")],
)
def test_hotp_rfc4226(counter, expected):
    assert totp.hotp(RFC_SECRET_ASCII, counter) == expected


@pytest.mark.parametrize(
    "timestamp,expected",
    [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ],
)
def test_totp_rfc6238(timestamp, expected):
    # El RFC usa 8 dígitos; con 6 dígitos son los 6 últimos.
    assert totp.totp(RFC_SECRET_B32, timestamp) == expected


def test_windows():
    t = 1234567890
    previous = totp.hotp(RFC_SECRET_ASCII, totp.counter_at(t) - 1)
    following = totp.hotp(RFC_SECRET_ASCII, totp.counter_at(t) + 1)
    assert totp.match_window(RFC_SECRET_B32, totp.totp(RFC_SECRET_B32, t), t) == 0
    assert totp.match_window(RFC_SECRET_B32, previous, t) == -1
    assert totp.match_window(RFC_SECRET_B32, following, t) == 1
    assert totp.match_window(RFC_SECRET_B32, totp.hotp(RFC_SECRET_ASCII, totp.counter_at(t) + 2), t) is None


def test_otpauth_uri():
    uri = totp.build_otpauth_uri("JBSWY3DPEHPK3PXP", "ana", "TallerMFA")
    assert uri.startswith("otpauth://totp/TallerMFA%3Aana?")
    assert "secret=JBSWY3DPEHPK3PXP" in uri
