/** Decodificador Base32 (RFC 4648) desde cero: cada carácter aporta 5 bits. */
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export function normalizeBase32(input: string): string {
  return input.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '')
}

export function isValidBase32(input: string): boolean {
  const clean = normalizeBase32(input)
  return clean.length >= 16 && /^[A-Z2-7]+$/.test(clean)
}

export function base32Decode(input: string): Uint8Array {
  const clean = normalizeBase32(input)
  const bytes: number[] = []
  let buffer = 0
  let bits = 0
  for (const char of clean) {
    const value = ALPHABET.indexOf(char)
    if (value === -1) throw new Error(`Carácter Base32 inválido: "${char}"`)
    buffer = (buffer << 5) | value
    bits += 5
    if (bits >= 8) {
      bits -= 8
      bytes.push((buffer >>> bits) & 0xff)
    }
  }
  return new Uint8Array(bytes)
}
