import { useState } from 'react'
import { createFileRoute, redirect } from '@tanstack/react-router'
import type { Me } from '#/lib/useMe'
import { AdminUsers } from '#/components/Admin/AdminUsers'
import { AdminRoles } from '#/components/Admin/AdminRoles'
import { AdminOAuthClients } from '#/components/Admin/AdminOAuthClients'

export const Route = createFileRoute('/admin')({
  beforeLoad: async () => {
    const response = await fetch('/api/users/me', {
      credentials: 'same-origin',
    })
    if (response.status === 401) throw redirect({ to: '/login' })
    if (!response.ok) throw new Error('ログイン状態を確認できませんでした。')
    const me = (await response.json()) as Me
    if (!me.Roles.includes('admin')) throw redirect({ to: '/' })
  },
  errorComponent: () => (
    <p role="alert">管理者設定を開けませんでした。再読み込みしてください。</p>
  ),
  component: AdminPage,
})

function AdminPage() {
  const [tab, setTab] = useState<'users' | 'roles' | 'clients'>('users')
  return (
    <div className="grid gap-6">
      <h1 className="text-2xl font-bold">管理者設定</h1>
      <nav
        aria-label="管理者設定"
        className="flex flex-wrap gap-4 border-b pb-4"
      >
        {(
          [
            ['users', 'ユーザ管理'],
            ['roles', 'ロール管理'],
            ['clients', 'OAuth Client 設定'],
          ] as const
        ).map(([value, label]) => (
          <button
            key={value}
            type="button"
            aria-current={tab === value ? 'page' : undefined}
            className={tab === value ? 'font-bold underline' : 'text-blue-800'}
            onClick={() => setTab(value)}
          >
            {label}
          </button>
        ))}
      </nav>
      {tab === 'users' && <AdminUsers />}
      {tab === 'roles' && <AdminRoles />}
      {tab === 'clients' && <AdminOAuthClients />}
    </div>
  )
}
