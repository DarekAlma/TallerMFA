import { useMemo, useState } from 'react'
import { Alert, Pressable, StyleSheet, Text, View } from 'react-native'
import * as Clipboard from 'expo-clipboard'
import { base32Decode } from '../crypto/base32'
import type { OtpAccount } from '../crypto/otpauth'
import { counterAt, hotp } from '../crypto/totp'
import type { Theme } from '../theme'

interface Props {
  account: OtpAccount
  now: number
  theme: Theme
  onDelete: (account: OtpAccount) => void
}

export function AccountCard({ account, now, theme, onDelete }: Props) {
  const [copied, setCopied] = useState(false)
  const key = useMemo(() => base32Decode(account.secret), [account.secret])
  const counter = counterAt(now, account.period)
  // Solo se recalcula el HMAC cuando cambia la ventana de 30 s.
  const code = useMemo(() => hotp(key, counter, account.digits), [key, counter, account.digits])

  const elapsed = now % account.period
  const remaining = Math.ceil(account.period - elapsed)
  const progress = 1 - elapsed / account.period
  const urgent = remaining <= 5
  const barColor = urgent ? theme.danger : theme.accent
  const half = Math.ceil(code.length / 2)

  async function copy() {
    await Clipboard.setStringAsync(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }

  function confirmDelete() {
    Alert.alert('Eliminar cuenta', `¿Eliminar ${account.issuer} (${account.account})?`, [
      { text: 'Cancelar', style: 'cancel' },
      { text: 'Eliminar', style: 'destructive', onPress: () => onDelete(account) },
    ])
  }

  return (
    <Pressable
      onPress={copy}
      onLongPress={confirmDelete}
      accessibilityRole="button"
      accessibilityLabel={`Código ${code} para ${account.issuer}. Toca para copiar, mantén presionado para eliminar.`}
      style={({ pressed }) => [
        styles.card,
        { backgroundColor: theme.surface, borderColor: theme.border, opacity: pressed ? 0.85 : 1 },
      ]}
    >
      <View style={styles.header}>
        <Text style={[styles.issuer, { color: theme.text }]} numberOfLines={1}>
          {account.issuer}
        </Text>
        <Text style={[styles.account, { color: theme.muted }]} numberOfLines={1}>
          {account.account}
        </Text>
      </View>

      <View style={styles.codeRow}>
        <Text style={[styles.code, { color: urgent ? theme.danger : theme.text }]} selectable>
          {code.slice(0, half)} {code.slice(half)}
        </Text>
        <View style={[styles.timer, { borderColor: barColor }]}>
          <Text style={[styles.timerText, { color: barColor }]}>{remaining}</Text>
        </View>
      </View>

      <View style={[styles.track, { backgroundColor: theme.surface2 }]}>
        <View style={[styles.bar, { width: `${progress * 100}%`, backgroundColor: barColor }]} />
      </View>

      <Text style={[styles.meta, { color: theme.muted }]}>
        {copied ? 'Copiado ✓' : `C = ⌊t/${account.period}⌋ = ${counter} · toca para copiar`}
      </Text>
    </Pressable>
  )
}

const styles = StyleSheet.create({
  card: { borderWidth: 1, borderRadius: 16, padding: 18, gap: 10 },
  header: { gap: 2 },
  issuer: { fontSize: 16, fontWeight: '700' },
  account: { fontSize: 13 },
  codeRow: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' },
  code: { fontSize: 46, fontWeight: '700', letterSpacing: 4, fontVariant: ['tabular-nums'] },
  timer: { width: 44, height: 44, borderRadius: 22, borderWidth: 3, alignItems: 'center', justifyContent: 'center' },
  timerText: { fontSize: 16, fontWeight: '700', fontVariant: ['tabular-nums'] },
  track: { height: 6, borderRadius: 3, overflow: 'hidden' },
  bar: { height: 6, borderRadius: 3 },
  meta: { fontSize: 12, fontVariant: ['tabular-nums'] },
})
