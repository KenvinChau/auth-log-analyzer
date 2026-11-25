import { detectAll } from './detect'
import { parseLog } from './parser'
import { summarize } from './summary'

export function analyze(text: string, year: number) {
  const parsed = parseLog(text, year)
  return {
    parsed,
    findings: detectAll(parsed.events),
    summary: summarize(parsed.events),
  }
}

export type Analysis = ReturnType<typeof analyze>