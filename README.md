# TallerMFA: Arquitectura 2FA (TOTP) desde cero + Observabilidad con Prefect

Laboratorio del curso **Patrones Arquitectónicos Avanzados**. Prueba de concepto con 4 piezas:

| # | Pieza | Carpeta | Tecnología |
|---|-------|---------|------------|
| 1 | App móvil Authenticator (funciona en modo avión) | [`/mobile-authenticator`](mobile-authenticator) | React Native + Expo (SDK 58) |
| 2 | Base de datos de usuarios | [`/supabase`](supabase) | Supabase (PostgreSQL) |
| 3 | Sistema de login (web app) | [`/web-login`](web-login) | React + Vite → Vercel |
| 4 | Backend Step-Up Auth instrumentado con Prefect | [`/backend-prefect`](backend-prefect) | Python, FastAPI y Prefect 3 |

```
TallerMFA/
├── mobile-authenticator/      # App propia (TOTP sin librerías TOTP)
│   ├── App.tsx
│   ├── src/crypto/            # sha1.ts, hmac.ts, base32.ts, totp.ts, otpauth.ts (desde cero)
│   ├── src/screens/           # Escáner QR y entrada manual de la semilla
│   ├── src/components/        # Tarjeta con código grande y contador 30→0
│   └── scripts/verify-totp.ts # Vectores RFC 4226/6238
├── backend-prefect/
│   ├── app/main.py            # API FastAPI (endpoints)
│   ├── app/flows/             # @flow y @task de Prefect
│   ├── app/domain/            # Strategy, máquina de estados, Process Manager, excepciones
│   ├── app/infrastructure/    # Repositorio Supabase/SQLite, caché anti-replay, store pre-auth
│   ├── app/core/              # TOTP desde cero, JWT, bcrypt, cifrado Fernet
│   ├── tests/                 # 22 pruebas (RFC + pruebas de aceptación)
│   └── scripts/demo_acceptance.py
├── web-login/                 # Login + aprovisionamiento 2FA + bóveda
└── supabase/                  # schema.sql + consultas_utiles.sql
```

---

## 1. Flujo general y patrones

```
 Usuario web ──(1) POST /auth/login usuario+contraseña──▶ Backend ──▶ pre_auth_token (scope=pre_auth)
                                                              │
 App móvil (modo avión) ──(2) HMAC-SHA1(secreto, ⌊t/30⌋) ──▶ código de 6 dígitos
                                                              │
 Usuario web ──(3) POST /auth/verify-2fa código + pre_auth──▶ @flow verify-2fa-step-up (Prefect)
                                                              ├─ Task 1 validate_pre_auth_state
                                                              ├─ Task 2 check_anti_replay_cache
                                                              ├─ Task 3 execute_mfa_strategy (TOTP | Backup)
                                                              └─ Task 4 issue_elevated_session ──▶ access_token (mfa_verified: true)
 Usuario web ──(4) GET /api/boveda-secreta + access_token──▶ 200 OK
```

| Patrón | Dónde | Qué hace |
|--------|-------|----------|
| **Process Manager / Máquina de estados** | `app/domain/state_machine.py`, `app/domain/provisioning.py` | `NOT_CONFIGURED → PENDING_VERIFICATION → ACTIVE`. El setup deja la 2FA en `PENDING_VERIFICATION` y solo el **primer código válido** la pasa a `ACTIVE`. Mientras esté pendiente el login no exige 2FA, así nadie queda bloqueado si genera el QR y nunca lo escanea. Las transiciones inválidas lanzan `InvalidStateTransition`. |
| **Step-Up Authentication** | `app/core/tokens.py`, `app/main.py` | `/auth/login` solo entrega un `pre_auth_token` (`aud=mfa-verification`, `scope=pre_auth`, `mfa_verified=false`, 5 min, **un solo uso**, máx. 5 intentos). La bóveda solo acepta el `access_token` (`aud=api`, `scope=access`, `mfa_verified=true`). Como las audiencias son distintas, un token no sirve en lugar del otro. |
| **Strategy** | `app/domain/strategies.py` | `SecondFactorStrategy` (ABC) con `TOTPStrategy` (ventanas C-1, C, C+1) y `BackupCodeStrategy` (códigos de un solo uso, consumo atómico). `resolve_strategy(method)` elige la estrategia en tiempo de ejecución. |
| **Repository** | `app/infrastructure/repositories.py` | El dominio no sabe si la BD es Supabase o SQLite (SQLite se usa en tests). |
| **Idempotencia / Anti-Replay** | `app/infrastructure/anti_replay.py` | Diccionario en memoria `(user_id, código) → expira` con TTL de 90 s (3 ventanas). La marca es atómica (`mark_used` bajo lock), así que dos peticiones simultáneas con el mismo código no pueden pasar las dos. |

Seguridad extra: contraseñas con bcrypt, semilla TOTP **cifrada en reposo** (Fernet), códigos de respaldo guardados como hash, `hmac.compare_digest`, tiempo constante ante usuarios inexistentes, RLS activado en Supabase y parámetros sensibles de los flows como `SecretStr` (en la UI de Prefect aparecen como `**********`).

---

## 2. Base de datos en Supabase

1. Entra a <https://supabase.com>, pulsa **New project**, ponle un nombre (ej. `taller-mfa`), una contraseña de BD y una región, y créalo.
2. Abre **SQL Editor → New query**, pega todo el contenido de [`supabase/schema.sql`](supabase/schema.sql) y pulsa **Run**. Se crean estas tablas:
   - `users`: usuario y hash bcrypt.
   - `mfa_configurations`: semilla cifrada y `status` (`PENDING_VERIFICATION` | `ACTIVE`).
   - `backup_codes`: hash del código y `used_at`.
   - `auth_audit_log`: eventos con el `flow_run_id` de Prefect.
3. Ve a **Project Settings → API Keys** y copia:
   - La **Project URL** (`https://<ref>.supabase.co`), que va en `SUPABASE_URL`.
   - La **Secret key** (`sb_secret_...`) o la legacy **service_role**, que va en `SUPABASE_SERVICE_KEY`.
     ⚠️ Esta llave solo se usa en el backend. **Nunca** va en la web ni en la app.
4. (Opcional) Para la sustentación tienes consultas listas en [`supabase/consultas_utiles.sql`](supabase/consultas_utiles.sql): usuarios con su estado 2FA, bitácora de replays, códigos de respaldo usados y cómo reiniciar la 2FA de un usuario.

> RLS está activado **sin políticas**, así que las llaves públicas no pueden leer nada. El backend usa la llave secreta, que omite RLS.
> Si no configuras Supabase, el backend usa SQLite local (`local.db`) automáticamente.

---

## 3. Backend + Prefect (`/backend-prefect`)

Requisitos: Python 3.10 o superior.

```bash
cd backend-prefect
python -m venv .venv
.venv\Scripts\activate          # Windows  (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
copy .env.example .env          # Linux/Mac: cp .env.example .env
```

Edita `.env`: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` y un `JWT_SECRET` aleatorio:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

**Terminal 1: servidor de Prefect**

```bash
prefect server start
```

Dashboard: <http://127.0.0.1:4200>

**Terminal 2: API**

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Documentación interactiva: <http://localhost:8000/docs>. Comprobación rápida: <http://localhost:8000/health>.

### Endpoints

| Método | Ruta | Token | Flow de Prefect |
|--------|------|-------|-----------------|
| POST | `/auth/register` | — | — |
| POST | `/auth/login` | — | `login-password-step` |
| POST | `/auth/2fa/setup` | pre_auth | `mfa-provisioning-start` (devuelve QR y semilla) |
| POST | `/auth/2fa/activate` | pre_auth | `mfa-provisioning-activate` (`PENDING_VERIFICATION → ACTIVE`, devuelve códigos de respaldo y access_token) |
| POST | `/auth/verify-2fa` `{code, method: "totp"\|"backup"}` | pre_auth | `verify-2fa-step-up` (las 4 tasks de la guía) |
| GET | `/api/boveda-secreta` | access (`mfa_verified=true`) | — |

### Pruebas automáticas

```bash
python -m pytest -q
```

Las 22 pruebas cubren los vectores RFC 6238/4226, la máquina de estados, step-up, replay, backup, intentos máximos y el token de un solo uso.

```bash
python scripts/demo_acceptance.py
```

Este script recorre el flujo completo contra la API en marcha y deja en Prefect un run verde y uno rojo (replay).

---

## 4. Web de login (`/web-login`) y despliegue en Vercel

### Local

```bash
cd web-login
npm install
copy .env.example .env.local    # VITE_API_URL=http://localhost:8000
npm run dev                     # http://localhost:5173
```

La web tiene estas pantallas: Registro/Login → (si la 2FA no está activa) **Generar QR → Activar** → códigos de respaldo → **Bóveda**. Si la 2FA ya está activa, después de la contraseña va directo a **Verificación** (pestañas `TOTPStrategy` / `BackupCodeStrategy`). Incluye un botón *"Demo anti-replay: reenviar el último código usado"*.

### Despliegue en Vercel

1. Sube el repositorio a GitHub.
2. En <https://vercel.com>: **Add New → Project → Import** tu repositorio.
3. Configuración:
   - **Root Directory**: `web-login`
   - Framework: **Vite** (detectado automáticamente; ya hay un `vercel.json`)
   - **Environment Variables**: `VITE_API_URL` = la URL pública de tu backend
4. Pulsa **Deploy**.

Como el backend corre en tu PC (la guía dice que no hay que desplegarlo), la web en Vercel tiene que poder alcanzarlo. Hay dos opciones:

- **Opción A, túnel (recomendada para la demo):**

  ```bash
  cloudflared tunnel --url http://localhost:8000
  ```

  También sirve `ngrok http 8000`. Pon la URL `https://….trycloudflare.com` en `VITE_API_URL` en Vercel y vuelve a desplegar (Deployments → Redeploy).
- **Opción B, mismo PC:** `VITE_API_URL=http://localhost:8000`. Chrome pedirá permiso de *acceso a la red local*; acéptalo. El backend ya responde el header `Access-Control-Allow-Private-Network`.

Restringe CORS en `.env` del backend:

```
CORS_ORIGINS=https://tu-app.vercel.app,http://localhost:5173
```

> Alternativa por CLI: `npm i -g vercel` → `cd web-login` → `vercel` → `vercel env add VITE_API_URL` → `vercel --prod`.

---

## 5. App móvil (`/mobile-authenticator`) en Expo Go

### Algoritmo (implementado desde cero, sin otplib ni speakeasy)

| Paso | Archivo |
|------|---------|
| 1. Base32 → bytes K | `src/crypto/base32.ts` |
| 2. C = ⌊UnixTime / 30⌋ | `src/crypto/totp.ts` → `counterAt` |
| 3. C como 8 bytes Big-Endian | `counterToBytes` |
| 4. HMAC-SHA1(K, C) → 20 bytes | `src/crypto/hmac.ts` + `src/crypto/sha1.ts` (SHA-1 propio) |
| 5. offset = hash[19] & 0x0f, 4 bytes, & 0x7f, % 1 000 000, padStart(6) | `hotp` |

Todo se calcula en el teléfono con su reloj local, **sin red**. La app muestra el código en grande, un contador 30→0 con barra de progreso que regenera el código, el valor de C, permite escanear el QR (`otpauth://totp/...?secret=`) o pegar la semilla/URI a mano, y guarda las cuentas en el almacenamiento seguro del dispositivo (`expo-secure-store`).

Para verificar el algoritmo contra los vectores oficiales:

```bash
npm run test:totp
```

### Cómo verla en Expo Go

1. En tu celular, instala **Expo Go** desde Play Store o App Store. Debe ser la versión que soporte el **SDK 58**; la de la tienda siempre soporta el SDK más reciente.
2. En el PC:

   ```bash
   cd mobile-authenticator
   npm install
   npx expo start
   ```

3. Aparece un **código QR en la terminal**:
   - **Android**: abre Expo Go → *Scan QR code*.
   - **iPhone**: abre la app **Cámara** y apunta al QR; se abre en Expo Go.
4. El celular y el PC deben estar en la **misma red Wi-Fi**. Si la red lo bloquea (redes universitarias), usa:

   ```bash
   npx expo start --tunnel
   ```

5. Para usarla:
   - En la app, pulsa **Escanear QR** y apunta al QR que muestra la web.
   - Sin cámara (emulador), usa **Ingresar semilla** y pega la semilla Base32 que muestra la web, debajo del QR.
   - Toca la tarjeta para copiar el código. Mantenla presionada para eliminar la cuenta.

> **Modo avión:** una vez que la app cargó en Expo Go, el JavaScript queda en memoria y el cálculo es 100 % local. Activa el modo avión y los códigos se siguen generando.
> Si cierras Expo Go del todo, al reabrirlo necesita red para descargar el bundle. Para una app 100 % independiente puedes generar un APK con `npx eas-cli@latest build -p android --profile preview` (opcional).

---

## 6. Guion de las 4 pruebas de aceptación (sustentación)

Antes de empezar, arranca todo:

```bash
prefect server start
uvicorn app.main:app --port 8000
npx expo start
```

Abre la web (Vercel o local) y el dashboard de Prefect (<http://127.0.0.1:4200/runs>).

1. **Paridad estándar.** Haz login en la web y pulsa **Generar código QR**. Escanea el **mismo QR** con la app propia y con **Google/Microsoft Authenticator**. Los dos muestran los mismos 6 dígitos al mismo tiempo. Después escribe el código en la web y pulsa **Activar 2FA** (estado `PENDING_VERIFICATION → ACTIVE`).
2. **Modo avión.** Activa el modo avión en el celular y espera a que cambie la ventana de 30 s. Cierra sesión en la web, vuelve a iniciarla, escribe el código nuevo y entrarás a `GET /api/boveda-secreta` con `mfa_verified: true`.
3. **Anti-replay.**
   1. Cierra sesión y vuelve a hacer login.
   2. Pulsa **"Demo anti-replay: reenviar el último código usado"** o escribe el mismo código antes de que pasen 30 s.
   3. La web muestra **⛔ Ataque de repetición bloqueado** (`REPLAY_ATTACK_DETECTED`).
   4. En Prefect, el run `verify-2fa-totp` aparece **Failed** (rojo), exactamente en la tarea `check_anti_replay_cache`, con el log `REPLAY ATTACK: el código 12**** ya fue usado…`.
4. **Clock skew o código de respaldo.**
   - En Prefect, abre un run verde de `verify-2fa-step-up`. En los logs de `execute_mfa_strategy` aparece, por ejemplo: `Ventana que hizo match: C-1 -> el reloj del celular va ATRASADO ~30 s`. Para forzarlo, escribe el código justo después de que cambie la ventana, o adelanta/atrasa la hora del celular unos 30 s.
   - O usa la pestaña **BackupCodeStrategy** con uno de los códigos `XXXX-XXXX`. Funciona una sola vez; al segundo intento falla.

---

## 7. Solución de problemas

| Problema | Solución |
|----------|----------|
| Los flows no aparecen en Prefect | Verifica que `PREFECT_API_URL=http://127.0.0.1:4200/api` esté en `.env` y que `prefect server start` esté corriendo **antes** que uvicorn. |
| `NETWORK_ERROR` en la web | Revisa `VITE_API_URL`, que el backend corra y que `CORS_ORIGINS` incluya tu dominio. En Vercel, cambiar una variable exige *Redeploy*. |
| Código siempre inválido | Revisa la hora automática del celular y del PC. El backend acepta ±30 s (C-1, C, C+1). |
| Expo Go: "incompatible SDK" | Actualiza Expo Go desde la tienda. El proyecto usa el SDK 58. |
| Expo Go no conecta | Usa la misma Wi-Fi o `npx expo start --tunnel`. |
| `INVALID_PRE_AUTH_TOKEN` | El pre_auth_token dura 5 min y es de un solo uso. Vuelve a iniciar sesión. |
