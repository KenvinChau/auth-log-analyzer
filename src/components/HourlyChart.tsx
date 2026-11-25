import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { HourBucket } from '../lib/summary'

export function HourlyChart({ data }: { data: HourBucket[] }) {
  const multiDay = data.length > 24
  const rows = data.map((b) => {
    const hh = `${String(b.hour.getUTCHours()).padStart(2, '0')}:00`
    const day = multiDay ? `${b.hour.getUTCDate()}/${b.hour.getUTCMonth() + 1} ` : ''
    return { label: day + hh, failed: b.failed, accepted: b.accepted }
  })

  return (
    <div role="img" aria-label="Bar chart of failed and accepted logins per hour" className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
          <XAxis dataKey="label" stroke="#94a3b8" fontSize={12} interval="preserveStartEnd" />
          <YAxis stroke="#94a3b8" fontSize={12} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 8 }}
            labelStyle={{ color: '#e2e8f0' }}
            cursor={{ fill: '#1e293b' }}
          />
          <Legend />
          <Bar dataKey="failed" name="Failed" fill="#f87171" radius={[3, 3, 0, 0]} />
          <Bar dataKey="accepted" name="Accepted" fill="#34d399" radius={[3, 3, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}