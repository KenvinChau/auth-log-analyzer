import { useMemo, useState } from 'react'
import sample from '../samples/auth.log?raw'
import { FindingsList } from './components/FindingsList'
import { HourlyChart } from './components/HourlyChart'
import { InputPanel } from './components/InputPanel'
import { RankedTable } from './components/RankedTable'
import { StatCards } from './components/StatCards'
import { analyze } from './lib/analyze'

const SAMPLE_YEAR = 2026
const SAMPLE_SOURCE = { text: sample, label: 'sample log' }

export default function App() {
  const [source, setSource] = useState(SAMPLE_SOURCE)
  const [year, setYear] = useState(SAMPLE_YEAR)

  // Derived, not stored: changing the text or the year re-analyzes automatically
  const analysis = useMemo(() => analyze(source.text, year), [source.text, year])
  const { parsed, findings, summary } = analysis

  function loadSample() {
    setSource(SAMPLE_SOURCE)
    setYear(SAMPLE_YEAR)
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <main className="mx-auto max-w-6xl space-y-6 p-6">
        <header>
          <h1 className="text-3xl font-bold">Auth Log Analyzer</h1>
          <p className="mt-1 text-sm text-slate-400">
            {parsed.events.length} SSH events parsed from {parsed.total} lines ({parsed.skipped}{' '}
            skipped) · source: {source.label}
          </p>
        </header>

        <InputPanel
          year={year}
          onYearChange={setYear}
          onLoadSample={loadSample}
          onText={(text, label, suggestedYear) => {
            setSource({ text, label })
            if (suggestedYear !== undefined) setYear(suggestedYear)
          }}
        />

        {parsed.events.length === 0 ? (
          <p className="rounded-xl border border-slate-800 bg-slate-900 p-6 text-slate-300">
            No SSH login events found in {parsed.total} lines. This tool reads Linux{' '}
            <code>/var/log/auth.log</code> lines written by <code>sshd</code>.
          </p>
        ) : (
          <>
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

            <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
              <h2 className="mb-3 text-sm font-semibold text-slate-300">Logins per hour (UTC log time)</h2>
              <HourlyChart data={summary.hourly} />
            </section>

            <div className="grid gap-4 md:grid-cols-2">
              <RankedTable title="Top IPs by failed logins" items={summary.topIps} />
              <RankedTable title="Top targeted usernames" items={summary.topUsers} />
            </div>
          </>
        )}
      </main>
    </div>
  )
}