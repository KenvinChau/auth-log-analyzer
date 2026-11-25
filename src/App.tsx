import sample from '../samples/auth.log?raw'
import { FindingsList } from './components/FindingsList'
import { HourlyChart } from './components/HourlyChart'
import { RankedTable } from './components/RankedTable'
import { StatCards } from './components/StatCards'
import { analyze } from './lib/analyze'

const SAMPLE_YEAR = 2026
const analysis = analyze(sample, SAMPLE_YEAR)

export default function App() {
  const { parsed, findings, summary } = analysis

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <main className="mx-auto max-w-6xl space-y-6 p-6">
        <header>
          <h1 className="text-3xl font-bold">Auth Log Analyzer</h1>
          <p className="mt-1 text-sm text-slate-400">
            {parsed.events.length} events parsed from {parsed.total} lines ({parsed.skipped} skipped).
            Everything runs in your browser.
          </p>
        </header>

        <StatCards
          failed={summary.failed}
          accepted={summary.accepted}
          ipsWithFailures={summary.ipsWithFailures}
          findings={findings.length}
        />

        <section>
          <h2 className="mb-3 text-lg font-semibold">Findings</h2>
          <FindingsList findings={findings} />
        </section>

        <div className="grid gap-4 lg:grid-cols-3">
          <section className="rounded-xl border border-slate-800 bg-slate-900 p-4 lg:col-span-2">
            <h2 className="mb-3 text-sm font-semibold text-slate-300">Logins per hour (log time)</h2>
            <HourlyChart data={summary.hourly} />
          </section>
          <div className="space-y-4">
            <RankedTable title="Top IPs by failed logins" items={summary.topIps} />
            <RankedTable title="Top targeted usernames" items={summary.topUsers} />
          </div>
        </div>
      </main>
    </div>
  )
}