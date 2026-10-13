// Error bodies are {"error":"message"} today and {"error":{"code","message"}}
// after the unified error format (P2d); read both.
export function errorBodyMessage(data: unknown): string | undefined {
  if (!data || typeof data !== 'object') return undefined
  const error = (data as { error?: unknown }).error
  if (typeof error === 'string') return error
  if (error && typeof error === 'object') {
    const message = (error as { message?: unknown }).message
    if (typeof message === 'string') return message
  }
  return undefined
}

// apiErrorMessage returns the server's message for an axios error, else the
// error's own message, else fallback.
export function apiErrorMessage(err: unknown, fallback: string): string {
  const response = (err as { response?: { data?: unknown } } | undefined)?.response
  return (
    errorBodyMessage(response?.data) ??
    (err instanceof Error && err.message ? err.message : undefined) ??
    fallback
  )
}
