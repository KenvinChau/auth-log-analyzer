import type { AuthEvent } from './types'

export const T0 = Date.UTC(2026, 10, 23)
export const SEC = 1000
export const MIN = 60 * SEC
export const HOUR = 60 * MIN

export function event(kind: AuthEvent['kind'], ip: string, offsetMs: number, user = 'root'): AuthEvent {
  return {
    timestamp: new Date(T0 + offsetMs),
    host: 'web01',
    pid: 1,
    kind,
    user,
    ip,
    port: 22222,
    method: 'password',
  }
}

export const failed = (ip: string, offsetMs: number, user = 'root') => event('failed', ip, offsetMs, user)
export const accepted = (ip: string, offsetMs: number, user = 'deploy') =>
  event('accepted', ip, offsetMs, user)
export const series = (n: number, make: (i: number) => AuthEvent) =>
  Array.from({ length: n }, (_, i) => make(i))