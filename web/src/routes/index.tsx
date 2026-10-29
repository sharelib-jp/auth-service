import { createFileRoute, redirect } from '@tanstack/react-router'
import { Identification } from '#/components/Identification'

export const Route = createFileRoute('/')({
  beforeLoad: async () => {
    const response = await fetch('/api/users/me', {
      method: 'GET',
      credentials: 'same-origin',
    })

    if (response.status === 401) {
      throw redirect({
        to: '/login',
        replace: true,
      })
    }

    if (!response.ok) {
      throw new Error('ログイン状態の確認に失敗しました')
    }
  },

  pendingMs: 0,
  pendingComponent: () => <p>ログイン状態を確認しています…</p>,

  errorComponent: () => (
    <p role="alert">
      ログイン状態を確認できませんでした。再読み込みしてください。
    </p>
  ),

  component: Home,
})

function Home() {
  return (
    <div>
      <Identification />
    </div>
  )
}
