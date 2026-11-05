import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Button } from '#/atoms/Button'
import { Input } from '#/atoms/Input'
import { adminRequest } from '#/lib/admin'
import type { Role } from '#/lib/admin'

export function AdminRoles() {
  const client = useQueryClient()
  const [editing, setEditing] = useState<Role | null>(null)
  const [notice, setNotice] = useState('')
  const roles = useQuery({
    queryKey: ['admin', 'roles'],
    queryFn: ({ signal }) =>
      adminRequest<{ items: Array<Role> }>('/roles', 'GET', undefined, signal),
    retry: false,
  })
  const remove = useMutation({
    mutationFn: (id: string) =>
      adminRequest(`/roles/${encodeURIComponent(id)}`, 'DELETE'),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['admin', 'roles'] })
      setNotice('ロールを削除しました。')
    },
  })
  return (
    <section className="grid gap-5" aria-label="ロール管理">
      <h2 className="text-xl font-bold">ロール管理</h2>
      <p>
        admin はユーザと OAuth Client
        を管理できます。追加したロールには管理権限はありません。
      </p>
      {notice && <p role="status">{notice}</p>}
      {roles.isPending && <p role="status">読み込み中…</p>}
      {roles.error && <p role="alert">{roles.error.message}</p>}
      {remove.error && <p role="alert">{remove.error.message}</p>}
      <ul className="grid gap-3">
        {roles.data?.items.map((role) => (
          <li
            key={role.id}
            className="flex flex-wrap items-center gap-3 rounded border p-4"
          >
            <span className="mr-auto">
              {role.name}（{role.id}）
            </span>
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setEditing(role)}
            >
              名称変更
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={role.id === 'admin' || remove.isPending}
              onClick={() => {
                if (window.confirm(`「${role.name}」を削除しますか？`))
                  remove.mutate(role.id)
              }}
            >
              削除
            </Button>
          </li>
        ))}
      </ul>
      <Button
        type="button"
        size="md"
        variant="outline"
        onClick={() => setEditing({ id: '', name: '' })}
      >
        ロールを追加
      </Button>
      {editing && (
        <RoleEditor
          key={editing.id}
          role={editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setEditing(null)
            setNotice('ロールを保存しました。')
          }}
        />
      )}
    </section>
  )
}

function RoleEditor({
  role,
  onSaved,
  onClose,
}: {
  role: Role
  onSaved: () => void
  onClose: () => void
}) {
  const client = useQueryClient()
  const [value, setValue] = useState(role)
  const save = useMutation({
    mutationFn: () =>
      role.id
        ? adminRequest(`/roles/${encodeURIComponent(role.id)}`, 'PATCH', {
            name: value.name,
          })
        : adminRequest('/roles', 'POST', value),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['admin', 'roles'] })
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
      <h3 className="font-bold">{role.id ? '名称変更' : 'ロール追加'}</h3>
      <label className="grid gap-2">
        ロール ID（英小文字から始まる英小文字・数字・ハイフン・アンダースコア）
        <Input
          blockSize="md"
          required
          pattern="[a-z][a-z0-9_-]{0,63}"
          maxLength={64}
          disabled={Boolean(role.id) || save.isPending}
          value={value.id}
          onChange={(event) => setValue({ ...value, id: event.target.value })}
        />
      </label>
      <label className="grid gap-2">
        名称
        <Input
          blockSize="md"
          required
          maxLength={100}
          disabled={save.isPending}
          value={value.name}
          onChange={(event) => setValue({ ...value, name: event.target.value })}
        />
      </label>
      {save.error && <p role="alert">{save.error.message}</p>}
      <div className="flex gap-3">
        <Button
          type="submit"
          size="md"
          variant="solid-fill"
          disabled={save.isPending}
        >
          保存
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
