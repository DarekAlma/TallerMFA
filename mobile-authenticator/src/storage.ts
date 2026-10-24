// Persistencia local cifrada (Keychain en iOS / Keystore en Android). Nada sale del teléfono.
import * as SecureStore from 'expo-secure-store'
import type { OtpAccount } from './crypto/otpauth'

const KEY = 'otp_accounts_v1'

export async function loadAccounts(): Promise<OtpAccount[]> {
  try {
    const raw = await SecureStore.getItemAsync(KEY)
    return raw ? (JSON.parse(raw) as OtpAccount[]) : []
  } catch {
    return []
  }
}

export async function saveAccounts(accounts: OtpAccount[]): Promise<void> {
  await SecureStore.setItemAsync(KEY, JSON.stringify(accounts))
}

export function newId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
}
