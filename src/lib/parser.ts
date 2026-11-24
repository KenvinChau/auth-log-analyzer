import type { AuthEvent, ParseResult } from './types'

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

// "Nov 23 03:12:44 web01 sshd[2211]: <message>"; \s+ also matches the padded "Nov  4"
const LINE =
  /^(?<month>[A-Z][a-z]{2})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<host>\S+)\s+sshd\[(?<pid>\d+)\]:\s+(?<msg>.*)$/

const FAILED = /^Failed (?<method>\S+) for (?<invalid>invalid user )?(?<user>\S+) from (?<ip>\S+) port (?<port>\d+)/
const ACCEPTED = /^Accepted (?<method>\S+) for (?<user>\S+) from (?<ip>\S+) port (?<port>\d+)/
const INVALID = /^Invalid user (?<user>\S+) from (?<ip>\S+)(?: port (?<port>\d+))?/

export function parseLine(line: string, year: number): AuthEvent | null {
  const m = LINE.exec(line)
  if (!m?.groups) return null

  const { month, day, time, host, pid, msg } = m.groups
  const monthIndex = MONTHS.indexOf(month)
  if (monthIndex === -1) return null

  const [h, min, s] = time.split(':').map(Number)
  const timestamp = new Date(Date.UTC(year, monthIndex, Number(day), h, min, s))
  const base = { timestamp, host, pid: Number(pid) }

  let g = FAILED.exec(msg)?.groups
  if (g) {
    return {
      ...base,
      kind: 'failed',
      user: g.user,
      ip: g.ip,
      port: Number(g.port),
      method: g.method,
      userExists: g.invalid === undefined,
    }
  }

  g = ACCEPTED.exec(msg)?.groups
  if (g) {
    return { ...base, kind: 'accepted', user: g.user, ip: g.ip, port: Number(g.port), method: g.method }
  }

  g = INVALID.exec(msg)?.groups
  if (g) {
    return {
      ...base,
      kind: 'invalid-user',
      user: g.user,
      ip: g.ip,
      port: g.port ? Number(g.port) : undefined,
    }
  }

  return null
}

export function parseLog(text: string, year: number): ParseResult {
  const events: AuthEvent[] = []
  let skipped = 0
  let total = 0

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (line === '') continue
    total++
    const event = parseLine(line, year)
    if (event) events.push(event)
    else skipped++
  }

  return { events, skipped, total }
}