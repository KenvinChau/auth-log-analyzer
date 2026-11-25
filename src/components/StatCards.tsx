interface StatCardsProps {
  failed: number
  accepted: number
  ipsWithFailures: number
  findings: number
}

export function StatCards({ failed, accepted, ipsWithFailures, findings }: StatCardsProps) {
  const cards = [
    { label: 'Failed logins', value: failed },
    { label: 'Accepted logins', value: accepted },
    { label: 'IPs with failures', value: ipsWithFailures },
    { label: 'Findings', value: findings },
  ]

  return (
    <section aria-label="Summary" className="grid grid-cols-2 gap-4 md:grid-cols-4">
      {cards.map((card) => (
        <div key={card.label} className="rounded-xl border border-slate-800 bg-slate-900 p-4">
          <p className="text-sm text-slate-400">{card.label}</p>
          <p className="mt-1 text-3xl font-semibold tabular-nums">{card.value.toLocaleString()}</p>
        </div>
      ))}
    </section>
  )
}