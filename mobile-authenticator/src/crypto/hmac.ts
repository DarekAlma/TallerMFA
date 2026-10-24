import { sha1 } from './sha1'

const BLOCK_SIZE = 64 // bytes, tamaño de bloque de SHA-1

/** HMAC-SHA1 (RFC 2104): H((K ⊕ opad) || H((K ⊕ ipad) || m)) */
export function hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Llaves más largas que el bloque se resumen primero; las cortas se rellenan con ceros.
  const normalizedKey = new Uint8Array(BLOCK_SIZE)
  normalizedKey.set(key.length > BLOCK_SIZE ? sha1(key) : key)

  const inner = new Uint8Array(BLOCK_SIZE + message.length)
  const outer = new Uint8Array(BLOCK_SIZE + 20)
  for (let i = 0; i < BLOCK_SIZE; i++) {
    inner[i] = normalizedKey[i] ^ 0x36 // ipad
    outer[i] = normalizedKey[i] ^ 0x5c // opad
  }
  inner.set(message, BLOCK_SIZE)
  outer.set(sha1(inner), BLOCK_SIZE)
  return sha1(outer)
}
