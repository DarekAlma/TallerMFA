/**
 * SHA-1 (FIPS 180-4) implementado desde cero, sin dependencias.
 * Recibe y devuelve bytes; la salida siempre son 20 bytes (160 bits).
 */
const rotl = (x: number, n: number) => ((x << n) | (x >>> (32 - n))) >>> 0

export function sha1(message: Uint8Array): Uint8Array {
  // 1. Padding: mensaje + 0x80 + ceros + longitud en bits (64 bits Big-Endian),
  //    hasta completar un múltiplo de 64 bytes (bloques de 512 bits).
  const length = message.length
  const paddedLength = Math.ceil((length + 9) / 64) * 64
  const padded = new Uint8Array(paddedLength)
  padded.set(message)
  padded[length] = 0x80
  const view = new DataView(padded.buffer)
  const bitLength = length * 8
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 2 ** 32))
  view.setUint32(paddedLength - 4, bitLength >>> 0)

  // 2. Valores iniciales del hash
  let h0 = 0x67452301
  let h1 = 0xefcdab89
  let h2 = 0x98badcfe
  let h3 = 0x10325476
  let h4 = 0xc3d2e1f0

  const w = new Uint32Array(80)
  for (let block = 0; block < paddedLength; block += 64) {
    // 3. Expansión del bloque a 80 palabras de 32 bits
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(block + i * 4)
    for (let i = 16; i < 80; i++) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    // 4. 80 rondas de compresión
    let a = h0
    let b = h1
    let c = h2
    let d = h3
    let e = h4
    for (let i = 0; i < 80; i++) {
      let f: number
      let k: number
      if (i < 20) {
        f = (b & c) | (~b & d)
        k = 0x5a827999
      } else if (i < 40) {
        f = b ^ c ^ d
        k = 0x6ed9eba1
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d)
        k = 0x8f1bbcdc
      } else {
        f = b ^ c ^ d
        k = 0xca62c1d6
      }
      const temp = (rotl(a, 5) + f + e + k + w[i]) >>> 0
      e = d
      d = c
      c = rotl(b, 30)
      b = a
      a = temp
    }
    h0 = (h0 + a) >>> 0
    h1 = (h1 + b) >>> 0
    h2 = (h2 + c) >>> 0
    h3 = (h3 + d) >>> 0
    h4 = (h4 + e) >>> 0
  }

  const digest = new Uint8Array(20)
  const out = new DataView(digest.buffer)
  ;[h0, h1, h2, h3, h4].forEach((h, i) => out.setUint32(i * 4, h))
  return digest
}
