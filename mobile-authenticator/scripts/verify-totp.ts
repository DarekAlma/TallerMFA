/**
 * Verifica la implementación TOTP desde cero contra los vectores oficiales.
 *   npm run test:totp
 *   npm run test:totp -- JBSWY3DPEHPK3PXP   (imprime el código actual de una semilla)
 */
import { createHash, createHmac } from 'node:crypto'
import { sha1 } from '../src/crypto/sha1'
import { hmacSha1 } from '../src/crypto/hmac'
import { base32Decode } from '../src/crypto/base32'
import { hotp, totp } from '../src/crypto/totp'
import { parseOtpauthUri } from '../src/crypto/otpauth'

let failures = 0
function check(name: string, actual: string, expected: string) {
  const ok = actual === expected
  if (!ok) failures++
  console.log(`${ok ? '✔' : '✘'} ${name}: ${actual}${ok ? '' : ` (esperado ${expected})`}`)
}
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex')
const bytes = (s: string) => new TextEncoder().encode(s)

// SHA-1 (FIPS 180) y comparación contra node:crypto
check('SHA1("abc")', hex(sha1(bytes('abc'))), 'a9993e364706816aba3e25717850c26c9cd0d89d')
check('SHA1("")', hex(sha1(bytes(''))), 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
for (const len of [55, 56, 63, 64, 65, 1000]) {
  const data = bytes('x'.repeat(len))
  check(`SHA1(${len} bytes) vs node`, hex(sha1(data)), createHash('sha1').update(data).digest('hex'))
}
// HMAC-SHA1 (RFC 2202) y llave larga
check('HMAC RFC2202 #2', hex(hmacSha1(bytes('Jefe'), bytes('what do ya want for nothing?'))), 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79')
const longKey = new Uint8Array(100).fill(0xaa)
check('HMAC llave 100 bytes vs node', hex(hmacSha1(longKey, bytes('msg'))), createHmac('sha1', longKey).update('msg').digest('hex'))

// Base32
check('Base32 "JBSWY3DPEHPK3PXP"', hex(base32Decode('JBSWY3DPEHPK3PXP')), '48656c6c6f21deadbeef')
check('Base32 RFC4648 "MZXW6YTBOI======"', Buffer.from(base32Decode('MZXW6YTBOI======')).toString(), 'foobar')

// HOTP (RFC 4226 Apéndice D)
const rfcKey = bytes('12345678901234567890')
;['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'].forEach((code, i) =>
  check(`HOTP contador ${i}`, hotp(rfcKey, i), code),
)

// TOTP (RFC 6238 Apéndice B, SHA-1, últimos 6 dígitos)
const rfcB32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
const vectors: [number, string][] = [
  [59, '287082'], [1111111109, '081804'], [1111111111, '050471'],
  [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130'],
]
for (const [t, code] of vectors) check(`TOTP t=${t}`, totp(rfcB32, t), code)

// otpauth://
const parsed = parseOtpauthUri('otpauth://totp/TallerMFA%3Aana?secret=JBSWY3DPEHPK3PXP&issuer=TallerMFA&algorithm=SHA1&digits=6&period=30')
check('otpauth issuer/cuenta', `${parsed.issuer}/${parsed.account}/${parsed.secret}`, 'TallerMFA/ana/JBSWY3DPEHPK3PXP')

const seed = process.argv[2]
if (seed) console.log(`\nCódigo actual para ${seed}: ${totp(seed)}`)

console.log(failures ? `\n${failures} prueba(s) fallaron` : '\nTodas las pruebas pasaron ✅')
process.exit(failures ? 1 : 0)
