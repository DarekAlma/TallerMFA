import { useEffect, useState } from 'react'

/** Reloj local del dispositivo (Unix seconds con decimales). Sin red: modo avión OK. */
export function useNow(intervalMs = 250): number {
  const [now, setNow] = useState(() => Date.now() / 1000)
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), intervalMs)
    return () => clearInterval(id)
  }, [intervalMs])
  return now
}
