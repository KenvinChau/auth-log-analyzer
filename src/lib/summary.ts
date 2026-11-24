import type { AuthEvent } from './types'

export interface RankedItem {
  label: string
  count: number
}

export interface HourBucket {
  hour: Date // start of the UTC hour
  failed: number
  accepted: number
}

export interface Summary {
  failed: number
  accepted: number
  ipsWithFailures: number
  topIps: RankedItem[]
  topUsers: RankedItem[]
  hourly: HourBucket[]
}

const HOUR_MS = 3_600_000

function countBy(events: AuthEvent[], key: (e: AuthEvent) => string): Map<string, number> {
  const counts = new Map<string, number>()
  for (const e of events) {
    const k = key(e)
    counts.set(k, (counts.get(k) ?? 0) + 1)
  }
  return counts
}

function rank(counts: Map<string, number>, limit: number): RankedItem[] {
  return [...counts.entries()]
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
    .slice(0, limit)
}

function hourlyBuckets(events: AuthEvent[]): HourBucket[] {
  if (events.length === 0) return []

  let min = Infinity
  let max = -Infinity
  for (const e of events) {
    const t = e.timestamp.getTime()
    if (t < min) min = t
    if (t > max) max = t
  }

  const start = Math.floor(min / HOUR_MS) * HOUR_MS
  const end = Math.floor(max / HOUR_MS) * HOUR_MS
  const buckets: HourBucket[] = []
  for (let t = start; t <= end; t += HOUR_MS) {
    buckets.push({ hour: new Date(t), failed: 0, accepted: 0 })
  }

  for (const e of events) {
    const index = Math.floor((e.timestamp.getTime() - start) / HOUR_MS)
    if (e.kind === 'failed') buckets[index].failed++
    else if (e.kind === 'accepted') buckets[index].accepted++
  }
  return buckets
}

export function summarize(events: AuthEvent[], topN = 10): Summary {
  const failedEvents = events.filter((e) => e.kind === 'failed')
  const ipCounts = countBy(failedEvents, (e) => e.ip)
  const userCounts = countBy(failedEvents, (e) => e.user)

  return {
    failed: failedEvents.length,
    accepted: events.filter((e) => e.kind === 'accepted').length,
    ipsWithFailures: ipCounts.size,
    topIps: rank(ipCounts, topN),
    topUsers: rank(userCounts, topN),
    hourly: hourlyBuckets(events),
  }
}