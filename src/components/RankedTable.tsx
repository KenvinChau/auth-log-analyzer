import type { RankedItem } from '../lib/summary'

interface RankedTableProps {
  title: string
  items: RankedItem[]
}

export function RankedTable({ title, items }: RankedTableProps) {
  const max = items[0]?.count ?? 1

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <h3 className="mb-3 text-sm font-semibold text-slate-300">{title}</h3>
      {items.length === 0 ? (
        <p className="text-sm text-slate-500">No data</p>
      ) : (
        <ul className="space-y-2">
          {items.map((item) => (
            <li key={item.label}>
              <div className="flex justify-between gap-2 text-sm">
                <span className="truncate font-mono">{item.label}</span>
                <span className="tabular-nums text-slate-400">{item.count}</span>
              </div>
              <div className="mt-1 h-1.5 rounded bg-slate-800">
                <div
                  className="h-full rounded bg-red-400"
                  style={{ width: `${(item.count / max) * 100}%` }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}