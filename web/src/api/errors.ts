// Error bodies are {"error":"message"} today and {"error":{"code","message"}}
// after the unified error format (P2d); read both.
export function errorBodyMessage(data: unknown): string | undefined {
  if (typeof data === 'string') {
    // Requests made with responseType 'text' get the JSON error body as text.
    try {
      return errorBodyMessage(JSON.parse(data))
    } catch {
      return undefined
    }
  }
  if (!data || typeof data !== 'object') return undefined
  const error = (data as { error?: unknown }).error
  if (typeof error === 'string') return error
  if (error && typeof error === 'object') {
    const message = (error as { message?: unknown }).message
    if (typeof message === 'string') return message
  }
  return undefined
}

// apiErrorMessage returns the server's message for an axios error. An HTTP
// error without one shows fallback (not axios' "Request failed with status
// code …"); only errors without a response (network down) show their own
// message.
export function apiErrorMessage(err: unknown, fallback: string): string {
  const response = (err as { response?: { data?: unknown } } | undefined)?.response
  if (response) {
    return errorBodyMessage(response.data) ?? fallback
  }
  return err instanceof Error && err.message ? err.message : fallback
}
