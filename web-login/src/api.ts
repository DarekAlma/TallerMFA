// Cliente HTTP del backend FastAPI (Step-Up Auth).
export const API_URL = (import.meta.env.VITE_API_URL ?? 'http://localhost:8000').replace(/\/$/, '')

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  constructor(status: number, code: string, message: string) {
    super(message)
    this.status = status
    this.code = code
  }
}

async function request<T>(path: string, options: { method?: string; token?: string; body?: unknown } = {}): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_URL}${path}`, {
      method: options.method ?? 'POST',
      headers: {
        'Content-Type': 'application/json',
        // ngrok gratis responde con una página HTML de aviso a los navegadores; este header la omite.
        'ngrok-skip-browser-warning': 'true',
        ...(options.token ? { Authorization: `Bearer ${options.token}` } : {}),
      },
      body: options.body ? JSON.stringify(options.body) : undefined,
    })
  } catch {
    throw new ApiError(0, 'NETWORK_ERROR', `No se pudo conectar con el backend (${API_URL}). ¿Está corriendo?`)
  }
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    const detail = typeof data.detail === 'string' ? data.detail : 'Datos inválidos'
    throw new ApiError(response.status, data.error ?? 'HTTP_ERROR', detail)
  }
  return data as T
}

export type NextStep = 'VERIFY_2FA' | 'SETUP_2FA'

export interface LoginResponse {
  pre_auth_token: string
  expires_in: number
  mfa_status: 'NOT_CONFIGURED' | 'PENDING_VERIFICATION' | 'ACTIVE'
  next_step: NextStep
}

export interface SetupResponse {
  secret: string
  otpauth_uri: string
  status: string
  qr_png_base64: string
}

export interface SessionResponse {
  access_token: string
  expires_in: number
  method: 'totp' | 'backup'
  matched_window: string | null
  mfa_verified: boolean
  backup_codes?: string[]
}

export const api = {
  register: (username: string, password: string) =>
    request('/auth/register', { body: { username, password } }),
  login: (username: string, password: string) =>
    request<LoginResponse>('/auth/login', { body: { username, password } }),
  setup2fa: (preAuthToken: string) => request<SetupResponse>('/auth/2fa/setup', { token: preAuthToken }),
  activate2fa: (preAuthToken: string, code: string) =>
    request<SessionResponse>('/auth/2fa/activate', { token: preAuthToken, body: { code } }),
  verify2fa: (preAuthToken: string, code: string, method: 'totp' | 'backup') =>
    request<SessionResponse>('/auth/verify-2fa', { token: preAuthToken, body: { code, method } }),
  vault: (accessToken: string) =>
    request<Record<string, unknown>>('/api/boveda-secreta', { method: 'GET', token: accessToken }),
}

export function decodeJwt(token: string): Record<string, unknown> {
  try {
    const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(decodeURIComponent(escape(atob(payload))))
  } catch {
    return {}
  }
}
