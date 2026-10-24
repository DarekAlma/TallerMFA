import { useEffect, useState } from 'react'
import { FlatList, Pressable, StyleSheet, Text, View } from 'react-native'
import { StatusBar } from 'expo-status-bar'
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context'
import { AccountCard } from './src/components/AccountCard'
import type { OtpAccount } from './src/crypto/otpauth'
import { ManualEntryScreen } from './src/screens/ManualEntryScreen'
import { ScannerScreen } from './src/screens/ScannerScreen'
import { loadAccounts, newId, saveAccounts } from './src/storage'
import { useTheme } from './src/theme'
import { useNow } from './src/useNow'

type View_ = 'home' | 'scan' | 'manual'

export default function App() {
  return (
    <SafeAreaProvider>
      <Authenticator />
    </SafeAreaProvider>
  )
}

function Authenticator() {
  const theme = useTheme()
  const now = useNow()
  const [view, setView] = useState<View_>('home')
  const [accounts, setAccounts] = useState<OtpAccount[]>([])
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    loadAccounts().then((list) => {
      setAccounts(list)
      setLoaded(true)
    })
  }, [])

  function persist(next: OtpAccount[]) {
    setAccounts(next)
    saveAccounts(next)
  }

  function add(account: Omit<OtpAccount, 'id'>) {
    // Si se re-escanea la misma cuenta (nuevo QR), se reemplaza la semilla anterior.
    const others = accounts.filter((a) => !(a.issuer === account.issuer && a.account === account.account))
    persist([{ ...account, id: newId() }, ...others])
    setView('home')
  }

  if (view === 'scan') {
    return <ScannerScreen theme={theme} onScanned={add} onCancel={() => setView('home')} onManual={() => setView('manual')} />
  }
  if (view === 'manual') {
    return <ManualEntryScreen theme={theme} onSave={add} onCancel={() => setView('home')} />
  }

  return (
    <SafeAreaView style={[styles.fill, { backgroundColor: theme.bg }]}>
      <StatusBar style="auto" />
      <View style={styles.header}>
        <Text style={[styles.title, { color: theme.text }]}>Authenticator</Text>
        <Text style={[styles.subtitle, { color: theme.muted }]}>
          TOTP RFC 6238 · HMAC-SHA1 propio · 100% offline
        </Text>
      </View>

      <FlatList
        data={accounts}
        keyExtractor={(a) => a.id}
        contentContainerStyle={styles.list}
        renderItem={({ item }) => (
          <AccountCard account={item} now={now} theme={theme} onDelete={(a) => persist(accounts.filter((x) => x.id !== a.id))} />
        )}
        ListEmptyComponent={
          loaded ? (
            <View style={[styles.empty, { borderColor: theme.border }]}>
              <Text style={[styles.emptyTitle, { color: theme.text }]}>Sin cuentas todavía</Text>
              <Text style={[styles.emptyBody, { color: theme.muted }]}>
                En la web, inicia sesión y pulsa "Generar código QR". Luego escanéalo aquí o pega la semilla.
              </Text>
            </View>
          ) : undefined
        }
        ListFooterComponent={
          accounts.length ? (
            <Text style={[styles.footer, { color: theme.muted }]}>Mantén presionada una cuenta para eliminarla.</Text>
          ) : undefined
        }
      />

      <View style={[styles.bottomBar, { borderColor: theme.border, backgroundColor: theme.bg }]}>
        <Pressable style={[styles.button, { backgroundColor: theme.accent }]} onPress={() => setView('scan')}>
          <Text style={[styles.buttonText, { color: theme.accentText }]}>Escanear QR</Text>
        </Pressable>
        <Pressable style={[styles.button, styles.ghost, { borderColor: theme.border }]} onPress={() => setView('manual')}>
          <Text style={[styles.buttonText, { color: theme.text }]}>Ingresar semilla</Text>
        </Pressable>
      </View>
    </SafeAreaView>
  )
}

const styles = StyleSheet.create({
  fill: { flex: 1 },
  header: { paddingHorizontal: 20, paddingTop: 12, paddingBottom: 8, gap: 2 },
  title: { fontSize: 28, fontWeight: '800', letterSpacing: -0.5 },
  subtitle: { fontSize: 13 },
  list: { padding: 16, gap: 12, flexGrow: 1 },
  empty: { borderWidth: 1, borderStyle: 'dashed', borderRadius: 16, padding: 24, gap: 8, marginTop: 24 },
  emptyTitle: { fontSize: 17, fontWeight: '700' },
  emptyBody: { fontSize: 14, lineHeight: 20 },
  footer: { textAlign: 'center', fontSize: 12, marginTop: 4 },
  bottomBar: { flexDirection: 'row', gap: 10, padding: 16, borderTopWidth: StyleSheet.hairlineWidth },
  button: { flex: 1, padding: 14, borderRadius: 12, alignItems: 'center' },
  ghost: { borderWidth: 1 },
  buttonText: { fontSize: 16, fontWeight: '600' },
})
