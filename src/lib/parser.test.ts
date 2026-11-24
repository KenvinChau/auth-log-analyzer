import { describe, expect, it } from 'vitest'
import { parseLine, parseLog } from './parser'

const YEAR = 2026

describe('parseLine', () => {
  it('parses a failed password for an existing user', () => {
    const e = parseLine(
      'Nov 23 02:52:08 web01 sshd[2015]: Failed password for deploy from 198.51.100.22 port 49213 ssh2',
      YEAR,
    )
    expect(e).toMatchObject({
      kind: 'failed',
      user: 'deploy',
      ip: '198.51.100.22',
      port: 49213,
      method: 'password',
      userExists: true,
      host: 'web01',
      pid: 2015,
    })
  })

  it('parses a failed password for an invalid user', () => {
    const e = parseLine(
      'Nov 23 03:12:01 web01 sshd[2030]: Failed password for invalid user admin from 203.0.113.45 port 54911 ssh2',
      YEAR,
    )
    expect(e).toMatchObject({ kind: 'failed', user: 'admin', userExists: false })
  })

  it('parses an invalid-user line', () => {
    const e = parseLine(
      'Nov 23 03:12:01 web01 sshd[2026]: Invalid user admin from 203.0.113.45 port 54911',
      YEAR,
    )
    expect(e).toMatchObject({ kind: 'invalid-user', user: 'admin', ip: '203.0.113.45' })
  })

  it('parses an accepted login', () => {
    const e = parseLine(
      'Nov 23 03:18:03 web01 sshd[3004]: Accepted password for deploy from 203.0.113.45 port 57188 ssh2',
      YEAR,
    )
    expect(e).toMatchObject({ kind: 'accepted', user: 'deploy', method: 'password' })
  })

  it('handles the space-padded day used by syslog', () => {
    const e = parseLine(
      'Nov  4 03:12:44 web01 sshd[2211]: Accepted publickey for kenvin from 198.51.100.7 port 40222 ssh2',
      YEAR,
    )
    expect(e?.timestamp).toEqual(new Date(Date.UTC(2026, 10, 4, 3, 12, 44)))
  })

  it('returns null for lines it does not understand', () => {
    expect(parseLine('garbage', YEAR)).toBeNull()
    expect(
      parseLine('Nov 23 03:12:00 web01 CRON[123]: pam_unix(cron:session): session opened', YEAR),
    ).toBeNull()
  })
})

describe('parseLog', () => {
  it('handles Windows line endings and blank lines', () => {
    const text = [
      'Nov 23 03:12:00 web01 sshd[1]: Invalid user oracle from 203.0.113.45 port 35229',
      '',
      'Nov 23 03:12:00 web01 sshd[2]: Failed password for invalid user oracle from 203.0.113.45 port 35229 ssh2',
      '',
    ].join('\r\n')
    const result = parseLog(text, YEAR)
    expect(result.events).toHaveLength(2)
    expect(result.total).toBe(2)
    expect(result.skipped).toBe(0)
  })

  it('counts skipped lines', () => {
    const text = [
      'Nov 23 03:12:00 web01 sshd[2]: Failed password for root from 203.0.113.45 port 35229 ssh2',
      'Nov 23 03:12:01 web01 CRON[9]: something unrelated',
      'not a log line at all',
    ].join('\n')
    const result = parseLog(text, YEAR)
    expect(result.events).toHaveLength(1)
    expect(result.skipped).toBe(2)
    expect(result.total).toBe(3)
  })
})