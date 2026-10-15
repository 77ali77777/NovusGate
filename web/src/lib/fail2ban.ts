// jailSaveResult reads PUT /system/fail2ban/jail/settings: Fail2Ban may
// refuse some values, and the server then answers 206 {status:"partial",
// errors} — a 2xx, so it must not be shown as saved.
export function jailSaveResult(res: { status?: string; errors?: (string | null)[] | null }): {
  ok: boolean
  errors: string[]
} {
  if (res.status !== 'partial') return { ok: true, errors: [] }
  return { ok: false, errors: (res.errors ?? []).filter((e): e is string => !!e) }
}
