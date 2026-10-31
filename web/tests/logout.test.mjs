import assert from 'node:assert/strict'
import { afterEach, describe, it, mock } from 'node:test'
import { logout } from '../src/lib/logout.ts'

afterEach(() => mock.restoreAll())

describe('ログアウト', () => {
  it('同一オリジンのログアウト API に POST する', async () => {
    const fetch = mock.method(
      globalThis,
      'fetch',
      async () => new Response(null, { status: 204 }),
    )
    await logout()
    assert.equal(fetch.mock.calls.length, 1)
    assert.deepEqual(fetch.mock.calls[0].arguments, [
      '/api/auth/logout',
      { method: 'POST', credentials: 'same-origin' },
    ])
  })

  it('セッションが既にない場合は成功として扱う', async () => {
    mock.method(
      globalThis,
      'fetch',
      async () => new Response(null, { status: 401 }),
    )
    await assert.doesNotReject(logout())
  })

  it('サーバーエラーや通信エラーは失敗として扱う', async () => {
    const fetch = mock.method(
      globalThis,
      'fetch',
      async () => new Response(null, { status: 500 }),
    )
    await assert.rejects(logout())
    fetch.mock.mockImplementation(async () => {
      throw new TypeError('network error')
    })
    await assert.rejects(logout())
  })
})
