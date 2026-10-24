import { useState } from 'react'
import { KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native'
import { SafeAreaView } from 'react-native-safe-area-context'
import { isValidBase32, normalizeBase32 } from '../crypto/base32'
import { parseOtpauthUri, type OtpAccount } from '../crypto/otpauth'
import { DEFAULT_DIGITS, DEFAULT_PERIOD } from '../crypto/totp'
import type { Theme } from '../theme'

interface Props {
  theme: Theme
  onSave: (account: Omit<OtpAccount, 'id'>) => void
  onCancel: () => void
}

export function ManualEntryScreen({ theme, onSave, onCancel }: Props) {
  const [issuer, setIssuer] = useState('TallerMFA')
  const [account, setAccount] = useState('')
  const [secret, setSecret] = useState('')
  const [error, setError] = useState('')

  function save() {
    const value = secret.trim()
    try {
      // También se acepta pegar la URI otpauth:// completa.
      if (value.toLowerCase().startsWith('otpauth://')) return onSave(parseOtpauthUri(value))
      if (!isValidBase32(value)) throw new Error('La semilla debe ser Base32 (A-Z, 2-7), mínimo 16 caracteres')
      onSave({
        issuer: issuer.trim() || 'Sin emisor',
        account: account.trim() || 'cuenta',
        secret: normalizeBase32(value),
        digits: DEFAULT_DIGITS,
        period: DEFAULT_PERIOD,
      })
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Dato inválido')
    }
  }

  const inputStyle = [styles.input, { backgroundColor: theme.surface2, color: theme.text, borderColor: theme.border }]

  return (
    <SafeAreaView style={[styles.fill, { backgroundColor: theme.bg }]}>
      <KeyboardAvoidingView style={styles.fill} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
        <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
          <Text style={[styles.title, { color: theme.text }]}>Ingresar semilla</Text>
          <Text style={[styles.body, { color: theme.muted }]}>
            Pega la semilla Base32 que muestra la web (o la URI otpauth:// completa). Útil en emuladores sin cámara.
          </Text>

          <View style={styles.field}>
            <Text style={[styles.label, { color: theme.text }]}>Emisor</Text>
            <TextInput style={inputStyle} value={issuer} onChangeText={setIssuer} placeholderTextColor={theme.muted} />
          </View>
          <View style={styles.field}>
            <Text style={[styles.label, { color: theme.text }]}>Cuenta / usuario</Text>
            <TextInput
              style={inputStyle}
              value={account}
              onChangeText={setAccount}
              autoCapitalize="none"
              placeholder="ana"
              placeholderTextColor={theme.muted}
            />
          </View>
          <View style={styles.field}>
            <Text style={[styles.label, { color: theme.text }]}>Semilla Base32</Text>
            <TextInput
              style={[inputStyle, styles.mono]}
              value={secret}
              onChangeText={(v) => {
                setSecret(v)
                setError('')
              }}
              autoCapitalize="characters"
              autoCorrect={false}
              multiline
              placeholder="JBSWY3DPEHPK3PXP…"
              placeholderTextColor={theme.muted}
            />
          </View>

          {error ? <Text style={[styles.error, { color: theme.danger }]}>{error}</Text> : null}

          <Pressable style={[styles.button, { backgroundColor: theme.accent }]} onPress={save}>
            <Text style={[styles.buttonText, { color: theme.accentText }]}>Guardar cuenta</Text>
          </Pressable>
          <Pressable style={[styles.button, styles.ghost, { borderColor: theme.border }]} onPress={onCancel}>
            <Text style={[styles.buttonText, { color: theme.text }]}>Cancelar</Text>
          </Pressable>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  )
}

const styles = StyleSheet.create({
  fill: { flex: 1 },
  content: { padding: 20, gap: 14 },
  title: { fontSize: 24, fontWeight: '700' },
  body: { fontSize: 14, lineHeight: 20 },
  field: { gap: 6 },
  label: { fontSize: 13, fontWeight: '600' },
  input: { borderWidth: 1, borderRadius: 12, padding: 12, fontSize: 16 },
  mono: { fontFamily: Platform.select({ ios: 'Menlo', default: 'monospace' }), minHeight: 64 },
  error: { fontSize: 14 },
  button: { padding: 14, borderRadius: 12, alignItems: 'center' },
  ghost: { borderWidth: 1 },
  buttonText: { fontSize: 16, fontWeight: '600' },
})
