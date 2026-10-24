import { useRef, useState } from 'react'
import { Pressable, StyleSheet, Text, View } from 'react-native'
import { CameraView, useCameraPermissions, type BarcodeScanningResult } from 'expo-camera'
import { SafeAreaView } from 'react-native-safe-area-context'
import { parseOtpauthUri, type OtpAccount } from '../crypto/otpauth'
import type { Theme } from '../theme'

interface Props {
  theme: Theme
  onScanned: (account: Omit<OtpAccount, 'id'>) => void
  onCancel: () => void
  onManual: () => void
}

export function ScannerScreen({ theme, onScanned, onCancel, onManual }: Props) {
  const [permission, requestPermission] = useCameraPermissions()
  const [error, setError] = useState('')
  const handled = useRef(false)

  function handleScan({ data }: BarcodeScanningResult) {
    if (handled.current) return
    try {
      const account = parseOtpauthUri(data)
      handled.current = true
      onScanned(account)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'QR inválido')
    }
  }

  if (!permission) return <View style={[styles.fill, { backgroundColor: theme.bg }]} />

  if (!permission.granted) {
    return (
      <SafeAreaView style={[styles.fill, styles.center, { backgroundColor: theme.bg }]}>
        <Text style={[styles.title, { color: theme.text }]}>Permiso de cámara</Text>
        <Text style={[styles.body, { color: theme.muted }]}>
          Se usa solo para leer el QR otpauth:// que genera el backend. Si estás en un emulador sin cámara, ingresa la
          semilla manualmente.
        </Text>
        <Pressable style={[styles.button, { backgroundColor: theme.accent }]} onPress={requestPermission}>
          <Text style={[styles.buttonText, { color: theme.accentText }]}>Permitir cámara</Text>
        </Pressable>
        <Pressable style={[styles.button, styles.ghost, { borderColor: theme.border }]} onPress={onManual}>
          <Text style={[styles.buttonText, { color: theme.text }]}>Ingresar semilla manual</Text>
        </Pressable>
        <Pressable onPress={onCancel}>
          <Text style={[styles.link, { color: theme.muted }]}>Cancelar</Text>
        </Pressable>
      </SafeAreaView>
    )
  }

  return (
    <View style={styles.fill}>
      <CameraView
        style={StyleSheet.absoluteFill}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={handleScan}
      />
      <SafeAreaView style={styles.overlay} pointerEvents="box-none">
        <Text style={styles.overlayTitle}>Apunta al QR del backend</Text>
        <View style={styles.frame} />
        {error ? <Text style={styles.error}>{error}</Text> : <View style={styles.errorSpacer} />}
        <View style={styles.actions}>
          <Pressable style={styles.overlayButton} onPress={onManual}>
            <Text style={styles.overlayButtonText}>Ingresar manual</Text>
          </Pressable>
          <Pressable style={styles.overlayButton} onPress={onCancel}>
            <Text style={styles.overlayButtonText}>Cancelar</Text>
          </Pressable>
        </View>
      </SafeAreaView>
    </View>
  )
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#000' },
  center: { alignItems: 'center', justifyContent: 'center', padding: 24, gap: 14 },
  title: { fontSize: 22, fontWeight: '700' },
  body: { fontSize: 15, textAlign: 'center', lineHeight: 22 },
  button: { alignSelf: 'stretch', padding: 14, borderRadius: 12, alignItems: 'center' },
  ghost: { borderWidth: 1 },
  buttonText: { fontSize: 16, fontWeight: '600' },
  link: { fontSize: 15, padding: 8 },
  overlay: { flex: 1, alignItems: 'center', justifyContent: 'space-between', paddingVertical: 24 },
  overlayTitle: { color: '#fff', fontSize: 18, fontWeight: '700', marginTop: 16 },
  frame: { width: 250, height: 250, borderWidth: 3, borderColor: '#fff', borderRadius: 24 },
  error: { color: '#fff', backgroundColor: 'rgba(180,35,24,0.9)', padding: 10, borderRadius: 10, marginHorizontal: 24, textAlign: 'center' },
  errorSpacer: { height: 40 },
  actions: { flexDirection: 'row', gap: 12 },
  overlayButton: { backgroundColor: 'rgba(0,0,0,0.6)', paddingVertical: 12, paddingHorizontal: 18, borderRadius: 12 },
  overlayButtonText: { color: '#fff', fontSize: 15, fontWeight: '600' },
})
