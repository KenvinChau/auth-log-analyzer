import { useState } from 'react'
import type { ChangeEvent } from 'react'

const MAX_BYTES = 5 * 1024 * 1024
const MAX_MB = MAX_BYTES / (1024 * 1024)
const YEARS = Array.from({ length: 21 }, (_, i) => 2015 + i) // 2015 to 2035

const buttonClass =
  'cursor-pointer rounded-lg bg-slate-800 px-4 py-2 text-sm font-medium hover:bg-slate-700 focus-within:outline-2 focus-within:outline-red-400 focus-visible:outline-2 focus-visible:outline-red-400'

interface InputPanelProps {
  year: number
  onYearChange: (year: number) => void
  onLoadSample: () => void
  onText: (text: string, label: string, year?: number) => void
}

export function InputPanel({ year, onYearChange, onLoadSample, onText }: InputPanelProps) {
  const [pasted, setPasted] = useState('')
  const [error, setError] = useState<string | null>(null)

  async function handleFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    e.target.value = '' // lets the user pick the same file again
    if (!file) return
    if (file.size > MAX_BYTES) {
      setError(`That file is too large (limit ${MAX_MB} MB).`)
      return
    }
    try {
      const text = await file.text()
      setError(null)
      const fileYear = new Date(file.lastModified).getFullYear()
      onText(text, file.name, YEARS.includes(fileYear) ? fileYear : undefined)
    } catch {
      setError('Could not read that file.')
    }
  }

  function handlePaste() {
    if (pasted.length > MAX_BYTES) {
      setError(`That text is too large (limit ${MAX_MB} MB).`)
      return
    }
    setError(null)
    onText(pasted, 'pasted text')
  }

  return (
    <section aria-label="Input" className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <button type="button" onClick={onLoadSample} className={buttonClass}>
          Load sample
        </button>

        <label className={buttonClass}>
          Upload auth.log
          <input type="file" accept=".log,.txt,text/plain" onChange={handleFile} className="sr-only" />
        </label>

        <label className="ml-auto flex items-center gap-2 text-sm text-slate-300">
          Log year
          <select
            value={year}
            onChange={(e) => onYearChange(Number(e.target.value))}
            className="rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5"
          >
            {YEARS.map((y) => (
              <option key={y} value={y}>
                {y}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="mt-2 text-xs text-slate-500">
        Syslog timestamps have no year. Uploads default to the file's last-modified year; adjust it
        if needed. Files are analyzed locally in your browser and never uploaded.
      </p>

      <details className="mt-3">
        <summary className="cursor-pointer text-sm text-slate-300">Or paste log text</summary>
        <textarea
          value={pasted}
          onChange={(e) => setPasted(e.target.value)}
          aria-label="Paste auth.log text"
          placeholder="Paste auth.log lines here"
          rows={5}
          spellCheck={false}
          className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 p-3 font-mono text-xs"
        />
        <button type="button" onClick={handlePaste} className={`${buttonClass} mt-2`}>
          Analyze pasted text
        </button>
      </details>

      {error && (
        <p role="alert" className="mt-3 text-sm text-red-300">
          {error}
        </p>
      )}
    </section>
  )
}