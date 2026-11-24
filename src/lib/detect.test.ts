import { describe, expect, it } from 'vitest'
import sample from '../../samples/auth.log?raw'
import {
  detectAll,
  detectBruteForce,
  detectDistributed,
  detectSlowAndLow,
  detectSuccessAfterFailures,
} from './detect'
import { parseLog } from './parser'
import type { AuthEvent } from './types'

const T0 = Date.UTC(2026, 10, 23)
const SEC = 1000
const MIN = 60 * SEC
const HOUR = 60 * MIN

function event(kind: AuthEvent['kind'], ip: string, offsetMs: number, user = 'root'): AuthEvent {
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
const failed = (ip: string, offsetMs: number, user = 'root') => event('failed', ip, offsetMs, user)
const accepted = (ip: string, offsetMs: number, user = 'deploy') => event('accepted', ip, offsetMs, user)
const series = (n: number, make: (i: number) => AuthEvent) => Array.from({ length: n }, (_, i) => make(i))

describe('detectBruteForce', () => {
  const IP = '203.0.113.9'

  it('flags 10 failures within a minute', () => {
    const findings = detectBruteForce(series(10, (i) => failed(IP, i * SEC)))
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({ rule: 'brute-force', count: 10, ips: [IP] })
  })

  it('ignores 9 failures', () => {
    expect(detectBruteForce(series(9, (i) => failed(IP, i * SEC)))).toHaveLength(0)
  })

  it('ignores a slow trickle', () => {
    expect(detectBruteForce(series(10, (i) => failed(IP, i * 10 * SEC)))).toHaveLength(0)
  })

  it('merges one continuous attack into a single finding', () => {
    const findings = detectBruteForce(series(30, (i) => failed(IP, i * SEC)))
    expect(findings).toHaveLength(1)
    expect(findings[0].count).toBe(30)
  })

  it('reports separate bursts separately', () => {
    const events = [
      ...series(10, (i) => failed(IP, i * SEC)),
      ...series(10, (i) => failed(IP, HOUR + i * SEC)),
    ]
    expect(detectBruteForce(events)).toHaveLength(2)
  })

  it('does not count invalid-user log lines as attempts', () => {
    expect(detectBruteForce(series(20, (i) => event('invalid-user', IP, i * SEC)))).toHaveLength(0)
  })

  it('tracks each IP on its own', () => {
    const events = [
      ...series(5, (i) => failed('203.0.113.1', i * SEC)),
      ...series(5, (i) => failed('203.0.113.2', i * SEC)),
    ]
    expect(detectBruteForce(events)).toHaveLength(0)
  })
})

describe('detectSlowAndLow', () => {
  const IP = '192.0.2.88'

  it('flags 20 failures spread over hours, which the burst rule misses', () => {
    const events = series(20, (i) => failed(IP, i * 10 * MIN))
    expect(detectBruteForce(events)).toHaveLength(0)
    expect(detectSlowAndLow(events)).toHaveLength(1)
  })

  it('ignores 20 failures packed into minutes (that is a burst)', () => {
    expect(detectSlowAndLow(series(20, (i) => failed(IP, i * SEC)))).toHaveLength(0)
  })

  it('ignores 19 failures even over many hours', () => {
    expect(detectSlowAndLow(series(19, (i) => failed(IP, i * 20 * MIN)))).toHaveLength(0)
  })
})

describe('detectDistributed', () => {
  it('flags 3 IPs failing against the same user within 30 minutes', () => {
    const events = [
      failed('203.0.113.101', 0),
      failed('203.0.113.102', 5 * MIN),
      failed('203.0.113.103', 10 * MIN),
    ]
    const findings = detectDistributed(events)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({ rule: 'distributed', user: 'root' })
    expect(findings[0].ips).toHaveLength(3)
  })

  it('ignores only 2 IPs', () => {
    expect(detectDistributed([failed('203.0.113.101', 0), failed('203.0.113.102', MIN)])).toHaveLength(0)
  })

  it('ignores 3 IPs spread across hours', () => {
    const events = [
      failed('203.0.113.101', 0),
      failed('203.0.113.102', 2 * HOUR),
      failed('203.0.113.103', 4 * HOUR),
    ]
    expect(detectDistributed(events)).toHaveLength(0)
  })
})

describe('detectSuccessAfterFailures', () => {
  const IP = '203.0.113.45'

  it('flags a login that follows 5 failures from the same IP', () => {
    const events = [...series(5, (i) => failed(IP, i * SEC, 'deploy')), accepted(IP, 30 * SEC)]
    const findings = detectSuccessAfterFailures(events)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({ severity: 'critical', user: 'deploy', ips: [IP] })
  })

  it('ignores a login after only 4 failures', () => {
    const events = [...series(4, (i) => failed(IP, i * SEC, 'deploy')), accepted(IP, 30 * SEC)]
    expect(detectSuccessAfterFailures(events)).toHaveLength(0)
  })

  it('ignores failures that came from a different IP', () => {
    const events = [...series(5, (i) => failed('203.0.113.99', i * SEC)), accepted(IP, 30 * SEC)]
    expect(detectSuccessAfterFailures(events)).toHaveLength(0)
  })
})

describe('detectAll on the generated sample log', () => {
  const { events } = parseLog(sample, 2026)
  const findings = detectAll(events)

  it('finds the brute-force burst', () => {
    expect(findings.some((f) => f.rule === 'brute-force' && f.ips.includes('203.0.113.45'))).toBe(true)
  })

  it('finds the slow-and-low attacker', () => {
    expect(findings.some((f) => f.rule === 'slow-and-low' && f.ips.includes('192.0.2.88'))).toBe(true)
  })

  it('finds the distributed attack on root', () => {
    const finding = findings.find((f) => f.rule === 'distributed' && f.user === 'root')
    expect(finding?.ips).toEqual(
      expect.arrayContaining(['203.0.113.101', '203.0.113.102', '203.0.113.103', '203.0.113.104', '203.0.113.105']),
    )
  })

  it('finds the compromise as the top finding', () => {
    expect(findings[0]).toMatchObject({
      rule: 'success-after-failures',
      severity: 'critical',
      user: 'deploy',
      ips: ['203.0.113.45'],
    })
  })

  it('raises no findings for the legitimate users', () => {
    expect(findings.some((f) => f.ips.some((ip) => ip.startsWith('198.51.100.')))).toBe(false)
  })
})