import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { api, ApiError, API_URL, decodeJwt, type LoginResponse, type SessionResponse, type SetupResponse } from './api'

type Screen =
  | { name: 'credentials' }
  | { name: 'setup'; login: LoginResponse; username: string }
  | { name: 'verify'; login: LoginResponse; username: string }
  | { name: 'backup-codes'; session: SessionResponse }
  | { name: 'vault'; session: SessionResponse }

const STEPS = ['Contraseña', 'Segundo factor', 'Bóveda']

export default function App() {
  const [screen, setScreen] = useState<Screen>({ name: 'credentials' })
  const step = screen.name === 'credentials' ? 0 : screen.name === 'vault' ? 2 : 1

  return (
    <div className="shell">
      <header className="brand">
        <span className="logo" aria-hidden>◈</span>
        <div>
          <h1>TallerMFA</h1>
          <p>Step-Up Authentication · TOTP RFC 6238 · Prefect</p>
        </div>
      </header>

      <ol className="stepper" aria-label="Progreso">
        {STEPS.map((label, i) => (
          <li key={label} className={i < step ? 'done' : i === step ? 'current' : ''}>
            <span>{i + 1}</span>
            {label}
          </li>
        ))}
      </ol>

      <main className="card">
        {screen.name === 'credentials' && (
          <CredentialsScreen
            onLoggedIn={(login, username) =>
              setScreen(
                login.next_step === 'VERIFY_2FA' ? { name: 'verify', login, username } : { name: 'setup', login, username },
              )
            }
          />
        )}
        {screen.name === 'setup' && (
          <SetupScreen
            login={screen.login}
            onActivated={(session) => setScreen({ name: 'backup-codes', session })}
            onExpired={() => setScreen({ name: 'credentials' })}
          />
        )}
        {screen.name === 'verify' && (
          <VerifyScreen
            login={screen.login}
            username={screen.username}
            onVerified={(session) => setScreen({ name: 'vault', session })}
            onRestart={() => setScreen({ name: 'credentials' })}
          />
        )}
        {screen.name === 'backup-codes' && (
          <BackupCodesScreen session={screen.session} onContinue={() => setScreen({ name: 'vault', session: screen.session })} />
        )}
        {screen.name === 'vault' && <VaultScreen session={screen.session} onLogout={() => setScreen({ name: 'credentials' })} />}
      </main>

      <footer className="footer">
        Backend: <code>{API_URL}</code>
      </footer>
    </div>
  )
}

/* ------------------------------------------------------------------ */
function ErrorBox({ error }: { error: ApiError | null }) {
  if (!error) return null
  const replay = error.code === 'REPLAY_ATTACK_DETECTED'
  return (
    <div className={`alert ${replay ? 'alert-replay' : ''}`} role="alert">
      <strong>{replay ? '⛔ Ataque de repetición bloqueado' : 'Error'}</strong>
      <span>{error.message}</span>
      <code>{error.code}</code>
    </div>
  )
}

function useAsync() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  async function run<T>(fn: () => Promise<T>): Promise<T | undefined> {
    setLoading(true)
    setError(null)
    try {
      return await fn()
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, 'UNKNOWN', String(e)))
      return undefined
    } finally {
      setLoading(false)
    }
  }
  return { loading, error, setError, run }
}

function Countdown({ seconds, onDone }: { seconds: number; onDone: () => void }) {
  const [left, setLeft] = useState(seconds)
  useEffect(() => {
    const id = setInterval(() => setLeft((s) => Math.max(0, s - 1)), 1000)
    return () => clearInterval(id)
  }, [])
  useEffect(() => {
    if (left === 0) onDone()
  }, [left, onDone])
  const mm = String(Math.floor(left / 60)).padStart(2, '0')
  const ss = String(left % 60).padStart(2, '0')
  return <span className="pill">pre_auth_token expira en {mm}:{ss}</span>
}

function CodeInput({ value, onChange, backup }: { value: string; onChange: (v: string) => void; backup?: boolean }) {
  return (
    <input
      className="code-input"
      autoFocus
      inputMode={backup ? 'text' : 'numeric'}
      autoComplete="one-time-code"
      placeholder={backup ? 'XXXX-XXXX' : '000000'}
      maxLength={backup ? 9 : 6}
      value={value}
      onChange={(e) => onChange(backup ? e.target.value.toUpperCase() : e.target.value.replace(/\D/g, ''))}
      aria-label={backup ? 'Código de respaldo' : 'Código de 6 dígitos'}
    />
  )
}

function TokenClaims({ token, title }: { token: string; title: string }) {
  const claims = decodeJwt(token)
  const shown = ['scope', 'aud', 'mfa_verified', 'mfa_status', 'amr', 'exp']
  return (
    <details className="claims">
      <summary>{title}</summary>
      <dl>
        {shown
          .filter((k) => k in claims)
          .map((k) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd>{k === 'exp' ? new Date(Number(claims[k]) * 1000).toLocaleTimeString() : JSON.stringify(claims[k])}</dd>
            </div>
          ))}
      </dl>
    </details>
  )
}

/* ------------------------------------------------------------------ */
function CredentialsScreen({ onLoggedIn }: { onLoggedIn: (login: LoginResponse, username: string) => void }) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [notice, setNotice] = useState('')
  const { loading, error, run } = useAsync()

  async function submit(e: FormEvent) {
    e.preventDefault()
    setNotice('')
    if (mode === 'register') {
      const ok = await run(() => api.register(username, password))
      if (ok) {
        setNotice('Cuenta creada. Ahora inicia sesión.')
        setMode('login')
      }
      return
    }
    const login = await run(() => api.login(username, password))
    if (login) onLoggedIn(login, username)
  }

  return (
    <form onSubmit={submit} className="stack">
      <div className="tabs" role="tablist">
        <button type="button" role="tab" aria-selected={mode === 'login'} onClick={() => setMode('login')}>
          Iniciar sesión
        </button>
        <button type="button" role="tab" aria-selected={mode === 'register'} onClick={() => setMode('register')}>
          Crear cuenta
        </button>
      </div>
      <label>
        Usuario
        <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required minLength={3} />
      </label>
      <label>
        Contraseña
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
          required
          minLength={8}
        />
      </label>
      {notice && <div className="alert alert-ok">{notice}</div>}
      <ErrorBox error={error} />
      <button className="primary" disabled={loading}>
        {loading ? 'Procesando…' : mode === 'login' ? 'Continuar' : 'Registrarme'}
      </button>
      <p className="hint">
        <code>POST /auth/login</code> no da acceso a la bóveda: devuelve un <b>pre_auth_token</b> que solo sirve para el
        segundo factor.
      </p>
    </form>
  )
}

/* ------------------------------------------------------------------ */
function SetupScreen({
  login,
  onActivated,
  onExpired,
}: {
  login: LoginResponse
  onActivated: (s: SessionResponse) => void
  onExpired: () => void
}) {
  const [setup, setSetup] = useState<SetupResponse | null>(null)
  const [code, setCode] = useState('')
  const [copied, setCopied] = useState(false)
  const { loading, error, run } = useAsync()

  async function generate() {
    const result = await run(() => api.setup2fa(login.pre_auth_token))
    if (result) setSetup(result)
  }

  async function activate(e: FormEvent) {
    e.preventDefault()
    const session = await run(() => api.activate2fa(login.pre_auth_token, code))
    if (session) onActivated(session)
  }

  return (
    <div className="stack">
      <div className="row-between">
        <h2>Activa tu doble factor</h2>
        <Countdown seconds={login.expires_in} onDone={onExpired} />
      </div>
      <p className="muted">
        Estado actual: <span className="badge">{setup?.status ?? login.mfa_status}</span>. Hasta que envíes el primer código
        válido la 2FA queda en <b>PENDING_VERIFICATION</b> y no te bloquea el acceso.
      </p>

      {!setup ? (
        <>
          <ErrorBox error={error} />
          <button className="primary" onClick={generate} disabled={loading}>
            {loading ? 'Generando…' : 'Generar código QR'}
          </button>
        </>
      ) : (
        <form onSubmit={activate} className="stack">
          <div className="qr-block">
            <img src={setup.qr_png_base64} alt="Código QR otpauth para la app autenticadora" width={200} height={200} />
            <ol className="instructions">
              <li>Abre tu app <b>mobile-authenticator</b> (y si quieres Google/Microsoft Authenticator).</li>
              <li>Escanea el QR o pega la semilla manualmente.</li>
              <li>Escribe el código de 6 dígitos que muestra la app.</li>
            </ol>
          </div>
          <div className="secret">
            <code>{setup.secret}</code>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                navigator.clipboard?.writeText(setup.secret)
                setCopied(true)
              }}
            >
              {copied ? 'Copiado' : 'Copiar semilla'}
            </button>
          </div>
          <CodeInput value={code} onChange={setCode} />
          <ErrorBox error={error} />
          <button className="primary" disabled={loading || code.length !== 6}>
            {loading ? 'Verificando…' : 'Activar 2FA'}
          </button>
        </form>
      )}
      <TokenClaims token={login.pre_auth_token} title="Ver claims del pre_auth_token" />
    </div>
  )
}

/* ------------------------------------------------------------------ */
const LAST_CODE_KEY = 'tallermfa:last-used-code'

function VerifyScreen({
  login,
  username,
  onVerified,
  onRestart,
}: {
  login: LoginResponse
  username: string
  onVerified: (s: SessionResponse) => void
  onRestart: () => void
}) {
  const [method, setMethod] = useState<'totp' | 'backup'>('totp')
  const [code, setCode] = useState('')
  const { loading, error, run } = useAsync()
  let lastCode = ''
  try {
    lastCode = sessionStorage.getItem(LAST_CODE_KEY) ?? ''
  } catch {
    /* sin storage */
  }

  async function submit(e: FormEvent, override?: string) {
    e.preventDefault()
    const value = override ?? code
    const session = await run(() => api.verify2fa(login.pre_auth_token, value, method))
    if (session) {
      try {
        if (method === 'totp') sessionStorage.setItem(LAST_CODE_KEY, value)
      } catch {
        /* sin storage */
      }
      onVerified(session)
    }
  }

  const dead = error && ['TOO_MANY_ATTEMPTS', 'INVALID_PRE_AUTH_TOKEN'].includes(error.code)

  return (
    <form onSubmit={submit} className="stack">
      <div className="row-between">
        <h2>Verificación en dos pasos</h2>
        <Countdown seconds={login.expires_in} onDone={onRestart} />
      </div>
      <p className="muted">
        Hola <b>{username}</b>. {method === 'totp' ? 'Ingresa el código de 6 dígitos de tu app (funciona en modo avión).' : 'Ingresa uno de tus códigos de respaldo de un solo uso.'}
      </p>
      <div className="tabs" role="tablist">
        <button type="button" role="tab" aria-selected={method === 'totp'} onClick={() => { setMethod('totp'); setCode('') }}>
          TOTPStrategy
        </button>
        <button type="button" role="tab" aria-selected={method === 'backup'} onClick={() => { setMethod('backup'); setCode('') }}>
          BackupCodeStrategy
        </button>
      </div>
      <CodeInput value={code} onChange={setCode} backup={method === 'backup'} />
      <ErrorBox error={error} />
      {dead ? (
        <button type="button" className="primary" onClick={onRestart}>
          Volver a iniciar sesión
        </button>
      ) : (
        <button className="primary" disabled={loading || code.length < 6}>
          {loading ? 'Verificando…' : 'Verificar'}
        </button>
      )}
      {method === 'totp' && lastCode && !dead && (
        <button type="button" className="ghost" onClick={(e) => submit(e as unknown as FormEvent, lastCode)} disabled={loading}>
          Demo anti-replay: reenviar el último código usado ({lastCode})
        </button>
      )}
      <TokenClaims token={login.pre_auth_token} title="Ver claims del pre_auth_token" />
    </form>
  )
}

/* ------------------------------------------------------------------ */
function BackupCodesScreen({ session, onContinue }: { session: SessionResponse; onContinue: () => void }) {
  const codes = session.backup_codes ?? []
  return (
    <div className="stack">
      <h2>2FA activa ✅</h2>
      <p className="muted">
        Estado <span className="badge badge-ok">ACTIVE</span>. Guarda estos códigos de respaldo: cada uno sirve <b>una sola
        vez</b> si pierdes el teléfono. No se volverán a mostrar.
      </p>
      <ul className="backup-grid">
        {codes.map((c) => (
          <li key={c}>
            <code>{c}</code>
          </li>
        ))}
      </ul>
      <button className="ghost" onClick={() => navigator.clipboard?.writeText(codes.join('\n'))}>
        Copiar códigos
      </button>
      <button className="primary" onClick={onContinue}>
        Ya los guardé, ir a la bóveda
      </button>
    </div>
  )
}

/* ------------------------------------------------------------------ */
function VaultScreen({ session, onLogout }: { session: SessionResponse; onLogout: () => void }) {
  const [vault, setVault] = useState<Record<string, unknown> | null>(null)
  const { loading, error, run } = useAsync()

  useEffect(() => {
    run(() => api.vault(session.access_token)).then((v) => v && setVault(v))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session.access_token])

  return (
    <div className="stack">
      <h2>GET /api/boveda-secreta</h2>
      <div className="facts">
        <Fact label="Método" value={session.method === 'totp' ? 'TOTPStrategy' : 'BackupCodeStrategy'} />
        <Fact label="Ventana" value={session.matched_window ?? '—'} />
        <Fact label="mfa_verified" value={String(session.mfa_verified)} />
      </div>
      {loading && <p className="muted">Abriendo la bóveda…</p>}
      <ErrorBox error={error} />
      {vault && <pre className="vault">{JSON.stringify(vault, null, 2)}</pre>}
      <TokenClaims token={session.access_token} title="Ver claims del access_token" />
      <button className="ghost" onClick={onLogout}>
        Cerrar sesión
      </button>
    </div>
  )
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="fact">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}
