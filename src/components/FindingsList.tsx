import type { Finding, Severity } from '../lib/detect'

// Full class names, so Tailwind can find them when it scans the source
const SEVERITY_STYLES: Record<Severity, string> = {
  critical: 'border-red-500/50 bg-red-500/10',
  high: 'border-orange-500/50 bg-orange-500/10',
  medium: 'border-yellow-500/50 bg-yellow-500/10',
}

// Log times are stored as UTC; display them as UTC so they match the log text
const dayFormat = new Intl.DateTimeFormat('en-GB', {
  day: 'numeric',
  month: 'short',
  year: 'numeric',
  timeZone: 'UTC',
})
const clockFormat = new Intl.DateTimeFormat('en-GB', {
  hour: '2-digit',
  minute: '2-digit',
  hour12: false,
  timeZone: 'UTC',
})

function formatRange(start: Date, end: Date): string {
  const from = `${dayFormat.format(start)}, ${clockFormat.format(start)}`
  if (start.getTime() === end.getTime()) return from
  const sameDay = dayFormat.format(start) === dayFormat.format(end)
  const to = sameDay ? clockFormat.format(end) : `${dayFormat.format(end)}, ${clockFormat.format(end)}`
  return `${from} to ${to}`
}

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return <p className="text-slate-400">No suspicious activity detected.</p>
  }

  return (
    <ul className="space-y-3">
      {findings.map((f, i) => (
        <li
          key={`${f.rule}-${f.start.getTime()}-${i}`}
          className={`rounded-xl border p-4 ${SEVERITY_STYLES[f.severity]}`}
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded bg-slate-950/60 px-2 py-0.5 text-xs font-bold tracking-wide uppercase">
              {f.severity}
            </span>
            <h3 className="font-semibold text-slate-100">{f.title}</h3>
            <span className="ml-auto text-xs text-slate-400">{f.mitre}</span>
          </div>
          <p className="mt-2 text-sm text-slate-200">{f.detail}</p>
          <p className="mt-1 text-xs text-slate-400">
            {formatRange(f.start, f.end)} UTC · IPs: {f.ips.join(', ')}
          </p>
        </li>
      ))}
    </ul>
  )
}