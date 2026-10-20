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

// errorBodyCode returns the stable code of a unified error response
// ({"error":{"code"}}) carried by an axios error, if there is one.
export function errorBodyCode(err: unknown): string | undefined {
  const data = (err as { response?: { data?: unknown } } | undefined)?.response?.data
  if (!data || typeof data !== 'object') return undefined
  const error = (data as { error?: unknown }).error
  if (error && typeof error === 'object') {
    const code = (error as { code?: unknown }).code
    if (typeof code === 'string') return code
  }
  return undefined
}

// translate turns a stable error code into a sentence in the panel's
// language (src/i18n sets it from the apiErrors namespace); a hook, so this
// file needs no imports and runs in web/tests.
let translate: ((code: string) => string | undefined) | undefined

export function setErrorTranslator(fn: ((code: string) => string | undefined) | undefined) {
  translate = fn
}

// apiErrorMessage returns the translation of an axios error's code when the
// panel has one, else the server's message. An HTTP error without one shows
// fallback (not axios' "Request failed with status code …"); only errors
// without a response (network down) show their own message.
export function apiErrorMessage(err: unknown, fallback: string): string {
  const response = (err as { response?: { data?: unknown } } | undefined)?.response
  if (response) {
    const code = errorBodyCode(err)
    const translated = code ? translate?.(code) : undefined
    return translated ?? errorBodyMessage(response.data) ?? fallback
  }
  return err instanceof Error && err.message ? err.message : fallback
}
