export type AuthEventKind = 'failed' | 'invalid-user' | 'accepted'

export interface AuthEvent {
  timestamp: Date
  host: string
  pid: number
  kind: AuthEventKind
  user: string
  ip: string
  port?: number
  method?: string // 'password' | 'publickey' ...
  userExists?: boolean // only set for 'failed': false means "invalid user"
}

export interface ParseResult {
  events: AuthEvent[]
  skipped: number // non-empty lines we could not parse
  total: number // non-empty lines seen
}