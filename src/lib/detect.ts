import type { AuthEvent } from './types'

export interface DetectionConfig {
  burstThreshold: number
  burstWindowMs: number
  slowMinFailures: number
  slowMinSpanMs: number
  distributedMinIps: number
  distributedWindowMs: number
  successMinFailures: number
  successLookbackMs: number
}

export const DEFAULT_CONFIG: DetectionConfig = {
  burstThreshold: 10,
  burstWindowMs: 60_000,
  slowMinFailures: 20,
  slowMinSpanMs: 2 * 3_600_000,
  distributedMinIps: 3,
  distributedWindowMs: 30 * 60_000,
  successMinFailures: 5,
  successLookbackMs: 10 * 60_000,
}

export type FindingRule = 'brute-force' | 'slow-and-low' | 'distributed' | 'success-after-failures'
export type Severity = 'medium' | 'high' | 'critical'

export interface Finding {
  rule: FindingRule
  severity: Severity
  title: string
  detail: string
  mitre: string
  ips: string[]
  user?: string
  start: Date
  end: Date
  count: number
}

const time = (e: AuthEvent) => e.timestamp.getTime()
const byTime = (a: AuthEvent, b: AuthEvent) => time(a) - time(b)

function groupBy(events: AuthEvent[], key: (e: AuthEvent) => string): Map<string, AuthEvent[]> {
  const groups = new Map<string, AuthEvent[]>()
  for (const e of events) {
    const k = key(e)
    const group = groups.get(k)
    if (group) group.push(e)
    else groups.set(k, [e])
  }
  return groups
}

// Only 'failed' events are attempts; 'invalid-user' lines would double-count.
const failures = (events: AuthEvent[]) => events.filter((e) => e.kind === 'failed')

interface Episode {
  from: number
  to: number
}

export function detectBruteForce(events: AuthEvent[], config = DEFAULT_CONFIG): Finding[] {
  const findings: Finding[] = []

  for (const [ip, list] of groupBy(failures(events), (e) => e.ip)) {
    const sorted = [...list].sort(byTime) // never assume the input is ordered
    const episodes: Episode[] = []
    let current: Episode | null = null
    let left = 0

    for (let right = 0; right < sorted.length; right++) {
      while (time(sorted[right]) - time(sorted[left]) > config.burstWindowMs) left++

      if (right - left + 1 >= config.burstThreshold) {
        if (current && left <= current.to) {
          current.to = right // still the same attack: extend it
        } else {
          current = { from: left, to: right }
          episodes.push(current)
        }
      }
    }

    for (const { from, to } of episodes) {
      const count = to - from + 1
      const seconds = Math.max(1, Math.round((time(sorted[to]) - time(sorted[from])) / 1000))
      findings.push({
        rule: 'brute-force',
        severity: 'high',
        title: 'Brute-force burst',
        detail: `${count} failed logins from ${ip} in ${seconds} s`,
        mitre: 'T1110 Brute Force',
        ips: [ip],
        start: sorted[from].timestamp,
        end: sorted[to].timestamp,
        count,
      })
    }
  }
  return findings
}

export function detectSlowAndLow(events: AuthEvent[], config = DEFAULT_CONFIG): Finding[] {
  const findings: Finding[] = []

  for (const [ip, list] of groupBy(failures(events), (e) => e.ip)) {
    const sorted = [...list].sort(byTime)
    const first = sorted[0]
    const last = sorted[sorted.length - 1]
    const span = time(last) - time(first)

    if (sorted.length >= config.slowMinFailures && span >= config.slowMinSpanMs) {
      findings.push({
        rule: 'slow-and-low',
        severity: 'medium',
        title: 'Slow, persistent guessing',
        detail: `${sorted.length} failed logins from ${ip} spread over ${(span / 3_600_000).toFixed(1)} h`,
        mitre: 'T1110 Brute Force',
        ips: [ip],
        start: first.timestamp,
        end: last.timestamp,
        count: sorted.length,
      })
    }
  }
  return findings
}

interface IpEpisode {
  start: number
  end: number
  ips: Set<string>
}

export function detectDistributed(events: AuthEvent[], config = DEFAULT_CONFIG): Finding[] {
  const findings: Finding[] = []

  for (const [user, list] of groupBy(failures(events), (e) => e.user)) {
    const sorted = [...list].sort(byTime)
    const inWindow = new Map<string, number>() // ip -> failures currently in the window
    const episodes: IpEpisode[] = []
    let current: IpEpisode | null = null
    let left = 0

    for (let right = 0; right < sorted.length; right++) {
      const ip = sorted[right].ip
      inWindow.set(ip, (inWindow.get(ip) ?? 0) + 1)

      while (time(sorted[right]) - time(sorted[left]) > config.distributedWindowMs) {
        const leaving = sorted[left].ip
        const remaining = (inWindow.get(leaving) ?? 1) - 1
        if (remaining === 0) inWindow.delete(leaving)
        else inWindow.set(leaving, remaining)
        left++
      }

      if (inWindow.size >= config.distributedMinIps) {
        if (current && time(sorted[left]) <= current.end) {
          current.end = time(sorted[right])
          for (const known of inWindow.keys()) current.ips.add(known)
        } else {
          current = { start: time(sorted[left]), end: time(sorted[right]), ips: new Set(inWindow.keys()) }
          episodes.push(current)
        }
      }
    }

    for (const ep of episodes) {
      const count = sorted.filter((e) => time(e) >= ep.start && time(e) <= ep.end).length
      findings.push({
        rule: 'distributed',
        severity: 'high',
        title: 'Distributed attack on one account',
        detail: `${ep.ips.size} different IPs failed to log in as "${user}"`,
        mitre: 'T1110 Brute Force',
        ips: [...ep.ips],
        user,
        start: new Date(ep.start),
        end: new Date(ep.end),
        count,
      })
    }
  }
  return findings
}

export function detectSuccessAfterFailures(events: AuthEvent[], config = DEFAULT_CONFIG): Finding[] {
  const failedByIp = groupBy(failures(events), (e) => e.ip)
  const findings: Finding[] = []

  for (const login of events.filter((e) => e.kind === 'accepted')) {
    const recent = (failedByIp.get(login.ip) ?? []).filter((f) => {
      const age = time(login) - time(f)
      return age >= 0 && age <= config.successLookbackMs
    })

    if (recent.length >= config.successMinFailures) {
      const earliest = recent.reduce((min, f) => Math.min(min, time(f)), Infinity)
      findings.push({
        rule: 'success-after-failures',
        severity: 'critical',
        title: 'Login succeeded after repeated failures',
        detail: `"${login.user}" logged in from ${login.ip} after ${recent.length} failed attempts from the same IP`,
        mitre: 'T1078 Valid Accounts',
        ips: [login.ip],
        user: login.user,
        start: new Date(earliest),
        end: login.timestamp,
        count: recent.length,
      })
    }
  }
  return findings
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1 }

export function detectAll(events: AuthEvent[], config = DEFAULT_CONFIG): Finding[] {
  return [
    ...detectSuccessAfterFailures(events, config),
    ...detectBruteForce(events, config),
    ...detectDistributed(events, config),
    ...detectSlowAndLow(events, config),
  ].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.start.getTime() - b.start.getTime(),
  )
}