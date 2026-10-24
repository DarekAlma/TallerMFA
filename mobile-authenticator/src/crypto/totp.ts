/**
 * TOTP (RFC 6238) paso a paso, tal como lo pide la guía.
 * Todo se calcula localmente: funciona en modo avión.
 */
import { base32Decode } from './base32'
import { hmacSha1 } from './hmac'

export const DEFAULT_PERIOD = 30
export const DEFAULT_DIGITS = 6

/** Paso 2: C = floor(UnixTime / 30) */
export function counterAt(unixSeconds: number, period = DEFAULT_PERIOD): number {
  return Math.floor(unixSeconds / period)
}

/** Paso 3: C como entero de 8 bytes (64 bits) Big-Endian */
export function counterToBytes(counter: number): Uint8Array {
  const bytes = new Uint8Array(8)
  const view = new DataView(bytes.buffer)
  view.setUint32(0, Math.floor(counter / 2 ** 32)) // 32 bits altos
  view.setUint32(4, counter >>> 0) // 32 bits bajos
  return bytes
}

/** Pasos 4 y 5: HMAC-SHA1(K, C) + truncamiento dinámico */
export function hotp(key: Uint8Array, counter: number, digits = DEFAULT_DIGITS): string {
  const hash = hmacSha1(key, counterToBytes(counter)) // 20 bytes
  const offset = hash[19] & 0x0f
  const binary =
    ((hash[offset] & 0x7f) << 24) | // quitar el bit de signo => entero positivo de 31 bits
    (hash[offset + 1] << 16) |
    (hash[offset + 2] << 8) |
    hash[offset + 3]
  return String(binary % 10 ** digits).padStart(digits, '0')
}

/** Paso 1 + todo lo anterior a partir de la semilla Base32 */
export function totp(secretBase32: string, unixSeconds = Date.now() / 1000, period = DEFAULT_PERIOD, digits = DEFAULT_DIGITS): string {
  return hotp(base32Decode(secretBase32), counterAt(unixSeconds, period), digits)
}

export function secondsRemaining(unixSeconds: number, period = DEFAULT_PERIOD): number {
  return period - (Math.floor(unixSeconds) % period)
}
