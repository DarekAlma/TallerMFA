import { useColorScheme } from 'react-native'

const light = {
  bg: '#f4f5f8',
  surface: '#ffffff',
  surface2: '#eef0f5',
  text: '#161a23',
  muted: '#5d6475',
  border: '#dde1ea',
  accent: '#3b5bfd',
  accentText: '#ffffff',
  warn: '#c2410c',
  danger: '#b42318',
}

const dark: typeof light = {
  bg: '#0e1117',
  surface: '#171b24',
  surface2: '#222837',
  text: '#e8ebf2',
  muted: '#9aa2b4',
  border: '#2b3140',
  accent: '#6f86ff',
  accentText: '#0e1117',
  warn: '#fb923c',
  danger: '#ff7a6e',
}

export type Theme = typeof light

export function useTheme(): Theme {
  return useColorScheme() === 'dark' ? dark : light
}
