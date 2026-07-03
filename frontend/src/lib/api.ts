import type { ApiErrorPayload } from '@/types'

export class ApiError extends Error {
  readonly setupRequired: boolean
  readonly status: number

  constructor(message: string, status: number, setupRequired = false) {
    super(message)
    this.status = status
    this.setupRequired = setupRequired
  }
}

export async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body !== undefined && !headers.has('content-type')) {
    headers.set('content-type', 'application/json')
  }

  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    headers,
  })
  const payload = (await response.json().catch(() => ({}))) as ApiErrorPayload

  if (!response.ok) {
    throw new ApiError(payload.error || response.statusText, response.status, Boolean(payload.setup_required))
  }

  return payload as T
}
