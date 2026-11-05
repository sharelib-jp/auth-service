import type { Me } from './useMe'

export type Role = { id: string; name: string }
export type UserPage = { items: Array<Me>; total: number }
export type OAuthClient = {
  id: string
  name: string
  public: boolean
  redirect_uris: Array<string>
  grant_types: Array<string>
  scopes: Array<string>
  audience: Array<string>
  status: 'active' | 'disabled'
}

export async function adminRequest<T>(
  path: string,
  method = 'GET',
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const response = await fetch(`/api/admin${path}`, {
    method,
    credentials: 'same-origin',
    signal,
    ...(body === undefined
      ? {}
      : {
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        }),
  })
  if (!response.ok) {
    if (response.status === 401) throw new Error('ログインし直してください。')
    if (response.status === 403) throw new Error('管理者権限が必要です。')
    const error = (await response.json().catch(() => null)) as {
      error?: string
    } | null
    throw new Error(error?.error || `処理に失敗しました (${response.status})`)
  }
  if (response.status === 204 || response.status === 201) return undefined as T
  return (await response.json()) as T
}
