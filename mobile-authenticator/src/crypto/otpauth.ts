/**
 * Parser de URIs otpauth://totp/<issuer>:<cuenta>?secret=...&issuer=...
 * (Key URI Format de Google Authenticator). Se hace a mano porque la clase
 * URL de React Native no soporta esquemas personalizados de forma fiable.
 */
import { DEFAULT_DIGITS, DEFAULT_PERIOD } from './totp'
import { isValidBase32, normalizeBase32 } from './base32'

export interface OtpAccount {
  id: string
  issuer: string
  account: string
  secret: string
  digits: number
  period: number
}

function decode(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, ' '))
  } catch {
    return value
  }
}

export function parseOtpauthUri(uri: string): Omit<OtpAccount, 'id'> {
  const match = /^otpauth:\/\/([^/]+)\/([^?]*)\?(.*)$/i.exec(uri.trim())
  if (!match) throw new Error('El QR no es una URI otpauth:// válida')
  const [, type, rawLabel, query] = match
  if (type.toLowerCase() !== 'totp') throw new Error(`Tipo "${type}" no soportado (solo TOTP)`)

  const params: Record<string, string> = {}
  for (const pair of query.split('&')) {
    const [k, v = ''] = pair.split('=')
    if (k) params[k.toLowerCase()] = decode(v)
  }

  const secret = normalizeBase32(params.secret ?? '')
  if (!isValidBase32(secret)) throw new Error('El parámetro "secret" falta o no es Base32 válido')
  const algorithm = (params.algorithm ?? 'SHA1').toUpperCase()
  if (algorithm !== 'SHA1') throw new Error(`Algoritmo ${algorithm} no soportado (solo SHA1)`)

  const label = decode(rawLabel)
  const [labelIssuer, labelAccount] = label.includes(':') ? label.split(/:(.*)/s) : ['', label]
  return {
    issuer: params.issuer || labelIssuer.trim() || 'Sin emisor',
    account: (labelAccount ?? '').trim() || label,
    secret,
    digits: Number(params.digits) || DEFAULT_DIGITS,
    period: Number(params.period) || DEFAULT_PERIOD,
  }
}
