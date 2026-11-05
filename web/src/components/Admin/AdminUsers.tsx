import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button } from '#/atoms/Button'
import { Input } from '#/atoms/Input'
import { adminRequest } from '#/lib/admin'
import type { Role, UserPage } from '#/lib/admin'
import type { Me } from '#/lib/useMe'

export function AdminUsers() {
  const [search, setSearch] = useState('')
  const [query, setQuery] = useState('')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)
  const [notice, setNotice] = useState('')
  const users = useQuery({
    queryKey: ['admin', 'users', query, offset],
    queryFn: ({ signal }) =>
      adminRequest<UserPage>(
        `/users?q=${encodeURIComponent(query)}&limit=25&offset=${offset}`,
        'GET',
        undefined,
        signal,
      ),
    retry: false,
  })
  const roles = useQuery({
    queryKey: ['admin', 'roles'],
    queryFn: ({ signal }) =>
      adminRequest<{ items: Array<Role> }>('/roles', 'GET', undefined, signal),
    retry: false,
  })

  return (
    <section className="grid gap-5" aria-label="ユーザ管理">
      <h2 className="text-xl font-bold">ユーザ管理</h2>
      <form
        className="flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault()
          setQuery(search)
          setOffset(0)
          setSelected(null)
        }}
      >
        <label className="grid flex-1 gap-2">
          ユーザ名・表示名・メールアドレスで検索
          <Input
            blockSize="md"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </label>
        <Button type="submit" size="md" variant="outline">
          検索
        </Button>
      </form>
      {notice && <p role="status">{notice}</p>}
      {users.isPending && <p role="status">読み込み中…</p>}
      {users.error && <p role="alert">{users.error.message}</p>}
      {roles.error && <p role="alert">{roles.error.message}</p>}
      {users.data && (
        <>
          <p>{users.data.total} 件</p>
          <ul className="grid gap-3">
            {users.data.items.map((user) => (
              <li
                key={user.ID}
                className="flex items-center justify-between gap-3 rounded border p-4"
              >
                <div className="min-w-0 break-words">
                  <p className="font-bold">
                    {user.Name}（{user.UserName}）
                  </p>
                  <p>{user.Email}</p>
                  <p className="text-sm">
                    ロール：{user.Roles.join('、') || 'なし'}
                  </p>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setSelected(user.ID)
                    setNotice('')
                  }}
                >
                  確認・編集
                </Button>
              </li>
            ))}
          </ul>
          <div className="flex items-center gap-4">
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={offset === 0}
              onClick={() => setOffset(offset - 25)}
            >
              前へ
            </Button>
            <span>{Math.floor(offset / 25) + 1} ページ</span>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={offset + 25 >= users.data.total}
              onClick={() => setOffset(offset + 25)}
            >
              次へ
            </Button>
          </div>
        </>
      )}
      {selected && roles.data && (
        <UserDetails
          key={selected}
          id={selected}
          roles={roles.data.items}
          onClose={() => setSelected(null)}
          onSaved={() => {
            setSelected(null)
            setNotice('ユーザ情報を保存しました。')
          }}
        />
      )}
    </section>
  )
}

function UserDetails({
  id,
  roles,
  onClose,
  onSaved,
}: {
  id: string
  roles: Array<Role>
  onClose: () => void
  onSaved: () => void
}) {
  const user = useQuery({
    queryKey: ['admin', 'user', id],
    queryFn: ({ signal }) =>
      adminRequest<Me>(
        `/users/${encodeURIComponent(id)}`,
        'GET',
        undefined,
        signal,
      ),
    retry: false,
  })
  return (
    <div className="rounded border p-5">
      <h3 className="mb-4 text-lg font-bold">ユーザ情報の確認・編集</h3>
      {user.isPending && <p role="status">読み込み中…</p>}
      {user.error && <p role="alert">{user.error.message}</p>}
      {user.data && (
        <UserEditor
          key={`${user.data.ID}-${user.data.UpdatedAt}`}
          user={user.data}
          roles={roles}
          onSaved={onSaved}
          onClose={onClose}
        />
      )}
      <button
        type="button"
        className="mt-4 text-blue-800 underline"
        onClick={() => void user.refetch()}
      >
        最新の情報を読み込む
      </button>
    </div>
  )
}

function UserEditor({
  user,
  roles,
  onSaved,
  onClose,
}: {
  user: Me
  roles: Array<Role>
  onSaved: () => void
  onClose: () => void
}) {
  const client = useQueryClient()
  const [values, setValues] = useState({
    UserName: user.UserName,
    Name: user.Name,
    Email: user.Email,
    Roles: user.Roles,
  })
  const save = useMutation({
    mutationFn: () =>
      adminRequest<Me>(`/users/${encodeURIComponent(user.ID)}`, 'PATCH', {
        ...values,
        UpdatedAt: user.UpdatedAt,
      }),
    onSuccess: async () => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ['admin', 'users'] }),
        client.invalidateQueries({ queryKey: ['admin', 'user', user.ID] }),
        client.invalidateQueries({ queryKey: ['me'] }),
      ])
      onSaved()
    },
  })
  return (
    <form
      className="grid gap-4"
      onSubmit={(event) => {
        event.preventDefault()
        save.mutate()
      }}
    >
      <dl className="break-all text-sm">
        <dt>ユーザ ID</dt>
        <dd>{user.ID}</dd>
        <dt>図書館 ID</dt>
        <dd>{user.LibraryIdFormatted}</dd>
        <dt>登録日時</dt>
        <dd>{new Date(user.CreatedAt).toLocaleString('ja-JP')}</dd>
        <dt>更新日時</dt>
        <dd>{new Date(user.UpdatedAt).toLocaleString('ja-JP')}</dd>
      </dl>
      <fieldset disabled={save.isPending} className="grid gap-4">
        {(
          [
            ['UserName', 'ユーザ名', 64],
            ['Name', '表示名', 100],
            ['Email', 'メールアドレス', 254],
          ] as const
        ).map(([key, label, maxLength]) => (
          <label key={key} className="grid gap-2">
            {label}
            <Input
              blockSize="md"
              required
              maxLength={maxLength}
              type={key === 'Email' ? 'email' : 'text'}
              value={values[key]}
              onChange={(event) =>
                setValues({ ...values, [key]: event.target.value })
              }
            />
          </label>
        ))}
        <fieldset className="grid gap-2">
          <legend className="mb-2 font-bold">ロール</legend>
          {roles.map((role) => (
            <label key={role.id} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={values.Roles.includes(role.id)}
                onChange={(event) =>
                  setValues({
                    ...values,
                    Roles: event.target.checked
                      ? [...values.Roles, role.id]
                      : values.Roles.filter((id) => id !== role.id),
                  })
                }
              />
              {role.name}（{role.id}）
            </label>
          ))}
        </fieldset>
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
