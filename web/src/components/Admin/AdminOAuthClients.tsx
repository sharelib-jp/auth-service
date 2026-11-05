import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button } from '#/atoms/Button'
import { Input } from '#/atoms/Input'
import { adminRequest } from '#/lib/admin'
import type { OAuthClient } from '#/lib/admin'

const emptyClient: OAuthClient = {
  id: '',
  name: '',
  public: false,
  redirect_uris: [],
  grant_types: ['authorization_code', 'refresh_token'],
  scopes: ['openid', 'profile', 'email'],
  audience: [],
  status: 'active',
}

export function AdminOAuthClients() {
  const queryClient = useQueryClient()
  const [editing, setEditing] = useState<OAuthClient | null>(null)
  const [notice, setNotice] = useState('')
  const clients = useQuery({
    queryKey: ['admin', 'clients'],
    queryFn: ({ signal }) =>
      adminRequest<{ items: Array<OAuthClient> }>(
        '/oauth/clients',
        'GET',
        undefined,
        signal,
      ),
    retry: false,
  })
  const status = useMutation({
    mutationFn: (client: OAuthClient) =>
      adminRequest(
        `/oauth/clients/${encodeURIComponent(client.id)}/status`,
        'PATCH',
        { status: client.status === 'active' ? 'disabled' : 'active' },
      ),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['admin', 'clients'] })
      setNotice('クライアントの状態を変更しました。')
    },
  })
  return (
    <section className="grid gap-5" aria-label="OAuth Client 設定">
      <h2 className="text-xl font-bold">OAuth Client 設定</h2>
      <p>
        登録したクライアントの情報を変更した場合や無効化した場合、発行済みのトークンは失効します。
      </p>
      {notice && <p role="status">{notice}</p>}
      {clients.isPending && <p role="status">読み込み中…</p>}
      {clients.error && <p role="alert">{clients.error.message}</p>}
      {status.error && <p role="alert">{status.error.message}</p>}
      {clients.data?.items.length === 0 && (
        <p>クライアントは登録されていません。</p>
      )}
      <ul className="grid gap-3">
        {clients.data?.items.map((client) => (
          <li key={client.id} className="grid gap-3 rounded border p-4">
            <div className="break-words">
              <p className="font-bold">
                {client.name}（{client.id}）
              </p>
              <p>
                {client.public ? 'Public' : 'Confidential'} ／{' '}
                {client.status === 'active' ? '有効' : '無効'}
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => {
                  setEditing(client)
                  setNotice('')
                }}
              >
                確認・編集
              </Button>
              <Button
                type="button"
                size="sm"
                variant="outline"
                disabled={status.isPending}
                onClick={() => {
                  if (
                    client.status !== 'active' ||
                    window.confirm(
                      `「${client.name}」を無効化しますか？発行済みトークンも失効します。`,
                    )
                  )
                    status.mutate(client)
                }}
              >
                {client.status === 'active' ? '無効化' : '有効化'}
              </Button>
            </div>
          </li>
        ))}
      </ul>
      <Button
        type="button"
        size="md"
        variant="outline"
        onClick={() => {
          setEditing(emptyClient)
          setNotice('')
        }}
      >
        クライアントを追加
      </Button>
      {editing && (
        <ClientEditor
          key={editing.id}
          client={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            setNotice('クライアントを保存しました。')
          }}
        />
      )}
    </section>
  )
}

function ClientEditor({
  client,
  onSaved,
  onClose,
}: {
  client: OAuthClient
  onSaved: () => void
  onClose: () => void
}) {
  const queryClient = useQueryClient()
  const [value, setValue] = useState({
    id: client.id,
    name: client.name,
    public: client.public,
  })
  const [redirects, setRedirects] = useState(client.redirect_uris.join('\n'))
  const [scopes, setScopes] = useState(client.scopes.join(' '))
  const [audience, setAudience] = useState(client.audience.join('\n'))
  const [refresh, setRefresh] = useState(
    client.grant_types.includes('refresh_token'),
  )
  const [secret, setSecret] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const save = useMutation({
    mutationFn: () =>
      adminRequest(
        client.id
          ? `/oauth/clients/${encodeURIComponent(client.id)}`
          : '/oauth/clients',
        client.id ? 'PUT' : 'POST',
        {
          ...value,
          redirect_uris: redirects
            .split('\n')
            .map((uri) => uri.trim())
            .filter(Boolean),
          grant_types: refresh
            ? ['authorization_code', 'refresh_token']
            : ['authorization_code'],
          scopes: scopes.trim().split(/\s+/).filter(Boolean),
          audience: audience
            .split('\n')
            .map((uri) => uri.trim())
            .filter(Boolean),
          ...(secret ? { secret } : {}),
        },
      ),
    onSuccess: async () => {
      setSecret('')
      await queryClient.invalidateQueries({ queryKey: ['admin', 'clients'] })
      onSaved()
    },
  })
  return (
    <form
      className="grid gap-4 rounded border p-5"
      onSubmit={(event) => {
        event.preventDefault()
        save.mutate()
      }}
    >
      <h3 className="text-lg font-bold">
        {client.id ? 'クライアントの編集' : 'クライアントの追加'}
      </h3>
      <fieldset className="grid gap-4" disabled={save.isPending}>
        <label className="grid gap-2">
          Client ID
          <Input
            blockSize="md"
            required
            maxLength={128}
            pattern="[a-zA-Z0-9_.\-]+"
            disabled={Boolean(client.id)}
            value={value.id}
            onChange={(event) => setValue({ ...value, id: event.target.value })}
          />
        </label>
        <label className="grid gap-2">
          名称
          <Input
            blockSize="md"
            required
            maxLength={200}
            value={value.name}
            onChange={(event) =>
              setValue({ ...value, name: event.target.value })
            }
          />
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={value.public}
            onChange={(event) => {
              setValue({ ...value, public: event.target.checked })
              setSecret('')
            }}
          />
          Public クライアント（シークレットを保持しないアプリ）
        </label>
        {!value.public && (
          <div className="grid gap-2">
            <label className="grid gap-2">
              Client Secret
              <Input
                blockSize="md"
                type={showSecret ? 'text' : 'password'}
                autoComplete="new-password"
                required={!client.id || client.public}
                minLength={32}
                maxLength={72}
                value={secret}
                onChange={(event) => setSecret(event.target.value)}
              />
            </label>
            <p className="text-sm">
              32〜72
              バイトのシークレットを入力してください。編集時は空欄で既存の値を保持します。保存後は再表示できないため、連携先の設定用に控えてください。
            </p>
            <div className="flex flex-wrap gap-3">
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => {
                  const bytes = crypto.getRandomValues(new Uint8Array(32))
                  setSecret(
                    btoa(String.fromCharCode(...bytes))
                      .replaceAll('+', '-')
                      .replaceAll('/', '_')
                      .replaceAll('=', ''),
                  )
                  setShowSecret(true)
                }}
              >
                シークレットを生成
              </Button>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={showSecret}
                  onChange={(event) => setShowSecret(event.target.checked)}
                />
                入力中の値を表示
              </label>
            </div>
          </div>
        )}
        <label className="grid gap-2">
          Redirect URI（1 行に 1 件、完全一致）
          <textarea
            className="w-full rounded border p-3"
            rows={3}
            required
            value={redirects}
            onChange={(event) => setRedirects(event.target.value)}
          />
        </label>
        <p className="text-sm">
          HTTPS の URI を指定してください。localhost のみ HTTP を使用できます。
        </p>
        <label className="grid gap-2">
          スコープ（スペース区切り）
          <Input
            blockSize="md"
            required
            value={scopes}
            onChange={(event) => setScopes(event.target.value)}
          />
        </label>
        <p className="text-sm">
          openid、profile、email、offline_access、または登録済みの業務スコープを指定します。
        </p>
        <label className="grid gap-2">
          Audience（登録済みリソースの URI、1 行に 1 件）
          <textarea
            className="w-full rounded border p-3"
            rows={3}
            value={audience}
            onChange={(event) => setAudience(event.target.value)}
          />
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={refresh}
            onChange={(event) => setRefresh(event.target.checked)}
          />
          リフレッシュトークンを許可
        </label>
        <p className="text-sm">
          認可コードフローを使用します。PKCE は必須です。
        </p>
      </fieldset>
      {save.error && <p role="alert">{save.error.message}</p>}
      <div className="flex gap-3">
        <Button
          type="submit"
          size="md"
          variant="solid-fill"
          disabled={save.isPending}
        >
          {save.isPending ? '保存中…' : '保存'}
        </Button>
        <Button
          type="button"
          size="md"
          variant="outline"
          disabled={save.isPending}
          onClick={onClose}
        >
          閉じる
        </Button>
      </div>
    </form>
  )
}
