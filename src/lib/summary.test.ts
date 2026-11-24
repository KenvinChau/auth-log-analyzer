import { describe, expect, it } from 'vitest'
import sample from '../../samples/auth.log?raw'
import { parseLog } from './parser'
import { summarize } from './summary'
import { HOUR, MIN, T0, accepted, event, failed } from './testHelpers'

describe('summarize', () => {
  it('counts failed and accepted logins but not invalid-user lines', () => {
    const s = summarize([
      failed('203.0.113.1', 0),
      failed('203.0.113.1', 1000),
      failed('203.0.113.2', 2000),
      event('invalid-user', '203.0.113.1', 0),
      accepted('198.51.100.7', 3000),
      accepted('198.51.100.7', 4000),
    ])
    expect(s.failed).toBe(3)
    expect(s.accepted).toBe(2)
  })

  it('counts only IPs that have failures', () => {
    const s = summarize([failed('203.0.113.1', 0), failed('203.0.113.2', 0), accepted('198.51.100.7', 0)])
    expect(s.ipsWithFailures).toBe(2)
  })

  it('ranks IPs by count, breaking ties alphabetically', () => {
    const s = summarize([
      failed('203.0.113.3', 0),
      failed('203.0.113.2', 0),
      failed('203.0.113.2', 1000),
      failed('203.0.113.1', 0),
      failed('203.0.113.1', 1000),
    ])
    expect(s.topIps.map((i) => i.label)).toEqual(['203.0.113.1', '203.0.113.2', '203.0.113.3'])
    expect(s.topIps[0].count).toBe(2)
  })

  it('limits the ranking to topN', () => {
    const s = summarize([failed('203.0.113.1', 0), failed('203.0.113.2', 0)], 1)
    expect(s.topIps).toHaveLength(1)
  })

  it('ranks the targeted usernames', () => {
    const s = summarize([
      failed('203.0.113.1', 0, 'root'),
      failed('203.0.113.1', 1000, 'root'),
      failed('203.0.113.1', 2000, 'admin'),
    ])
    expect(s.topUsers[0]).toEqual({ label: 'root', count: 2 })
  })

  it('fills empty hours with zeros', () => {
    const s = summarize([failed('203.0.113.1', 10 * MIN), failed('203.0.113.1', 3 * HOUR + 5 * MIN)])
    expect(s.hourly.map((b) => b.failed)).toEqual([1, 0, 0, 1])
    expect(s.hourly[0].hour).toEqual(new Date(T0))
  })

  it('separates failed and accepted logins within one hour', () => {
    const s = summarize([failed('203.0.113.1', 0), accepted('198.51.100.7', MIN)])
    expect(s.hourly).toHaveLength(1)
    expect(s.hourly[0]).toMatchObject({ failed: 1, accepted: 1 })
  })

  it('handles an empty log', () => {
    const s = summarize([])
    expect(s).toMatchObject({ failed: 0, accepted: 0, ipsWithFailures: 0, hourly: [] })
  })
})

describe('summarize on the generated sample log', () => {
  const s = summarize(parseLog(sample, 2026).events)

  it('puts the brute-force IP at the top', () => {
    expect(s.topIps[0].label).toBe('203.0.113.45')
  })

  it('peaks at 03:00 UTC, when the burst happened', () => {
    const peak = s.hourly.reduce((best, b) => (b.failed > best.failed ? b : best))
    expect(peak.hour.getUTCHours()).toBe(3)
  })
})