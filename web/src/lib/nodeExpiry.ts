// Expiry choices of the Edit Node dialog. Kept free of imports so it runs
// under `node --experimental-strip-types` in web/tests.

export type ExpiryChoice = 'keep' | 'forever' | '1h' | '1d' | '1w' | 'custom'

// ok: expiresAt is what to send (undefined: no change, null: no limit);
// otherwise error is the i18n key (nodes namespace) of the reason. A plain shape: the web tsconfig is not strict,
// so a discriminated union would not narrow.
export interface ExpiryResult {
  ok: boolean
  expiresAt?: string | null
  error?: string
}

const HOUR = 60 * 60 * 1000
const EXTENSIONS: Record<string, number> = { '1h': HOUR, '1d': 24 * HOUR, '1w': 7 * 24 * HOUR }

// initialExpiryChoice is always "keep": the dialog must not send (or
// validate) a date the user did not touch (B13).
export function initialExpiryChoice(_current: string | null | undefined): ExpiryChoice {
  return 'keep'
}

// computeExpiry turns the dialog's choice into the expires_at to send.
export function computeExpiry(opts: {
  choice: ExpiryChoice
  current: string | null | undefined
  customDate?: string
  now: Date
}): ExpiryResult {
  const { choice, current, customDate, now } = opts
  const currentTime = current ? new Date(current).getTime() : null
  if (choice === 'keep') return { ok: true, expiresAt: undefined }
  if (choice === 'forever') return { ok: true, expiresAt: null }
  if (choice in EXTENSIONS) {
    const base = Math.max(currentTime ?? now.getTime(), now.getTime())
    return { ok: true, expiresAt: new Date(base + EXTENSIONS[choice]).toISOString() }
  }
  if (!customDate) return { ok: false, error: 'nodes:edit.errors.dateRequired' }
  const selected = new Date(customDate)
  if (Number.isNaN(selected.getTime())) return { ok: false, error: 'nodes:edit.errors.dateInvalid' }
  if (selected.getTime() <= now.getTime()) {
    return { ok: false, error: 'nodes:edit.errors.mustBeFuture' }
  }
  // A limit that has not passed yet can only be extended.
  if (currentTime !== null && currentTime > now.getTime() && selected.getTime() < currentTime) {
    return { ok: false, error: 'nodes:edit.errors.onlyExtend' }
  }
  return { ok: true, expiresAt: selected.toISOString() }
}
