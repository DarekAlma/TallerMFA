"""Ejecuta por HTTP las pruebas de aceptación de la guía contra el backend en marcha.

    python scripts/demo_acceptance.py [--api http://localhost:8000]

Simula el celular calculando el TOTP localmente. Sirve para ensayar antes de la
sustentación y para dejar en el dashboard de Prefect un run verde y uno rojo
(replay) para mostrar.
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.core import totp  # noqa: E402


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # consola de Windows
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8000")
    api = httpx.Client(base_url=parser.parse_args().api, timeout=60)

    username, password = f"demo_{uuid.uuid4().hex[:6]}", "ClaveSegura123"
    api.post("/auth/register", json={"username": username, "password": password}).raise_for_status()
    print(f"1. Usuario creado: {username}")

    login = api.post("/auth/login", json={"username": username, "password": password}).json()
    pre = {"Authorization": f"Bearer {login['pre_auth_token']}"}
    print(f"2. Login -> pre_auth_token (next_step={login['next_step']})")
    print(f"   Bóveda con pre_auth_token -> {api.get('/api/boveda-secreta', headers=pre).status_code} (esperado 401)")

    setup = api.post("/auth/2fa/setup", headers=pre).json()
    secret = parse_qs(urlparse(setup["otpauth_uri"]).query)["secret"][0]
    print(f"3. Setup -> estado {setup['status']}, semilla {secret}")

    code = totp.totp(secret)
    activated = api.post("/auth/2fa/activate", headers=pre, json={"code": code}).json()
    print(f"4. Activación con {code} -> estado {activated['status']}, ventana {activated['matched_window']}")
    backup = activated["backup_codes"]

    # Prueba de Ataque de Repetición
    login = api.post("/auth/login", json={"username": username, "password": password}).json()
    pre = {"Authorization": f"Bearer {login['pre_auth_token']}"}
    replay = api.post("/auth/verify-2fa", headers=pre, json={"code": code})
    print(f"5. REPLAY del mismo código {code} -> {replay.status_code} {replay.json()['error']} (flow rojo en Prefect)")

    # Siguiente ventana: esperar a que cambie el contador para usar un código nuevo
    wait = totp.TIME_STEP - int(time.time()) % totp.TIME_STEP + 1
    print(f"   Esperando {wait}s a la siguiente ventana de 30 s…")
    time.sleep(wait)
    fresh = totp.totp(secret)
    ok = api.post("/auth/verify-2fa", headers=pre, json={"code": fresh}).json()
    print(f"6. verify-2fa con {fresh} -> ventana {ok['matched_window']}, mfa_verified={ok['mfa_verified']}")
    vault = api.get("/api/boveda-secreta", headers={"Authorization": f"Bearer {ok['access_token']}"})
    print(f"   GET /api/boveda-secreta -> {vault.status_code} {vault.json()['mensaje']}")

    # BackupCodeStrategy
    login = api.post("/auth/login", json={"username": username, "password": password}).json()
    pre = {"Authorization": f"Bearer {login['pre_auth_token']}"}
    b = api.post("/auth/verify-2fa", headers=pre, json={"code": backup[0], "method": "backup"})
    print(f"7. Código de respaldo {backup[0]} -> {b.status_code} método={b.json().get('method')}")

    print("\nAbre http://127.0.0.1:4200/runs para ver los flows y logs.")


if __name__ == "__main__":
    main()
