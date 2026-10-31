import { createFileRoute, redirect, Link } from '@tanstack/react-router'
import { IdentificationComponent } from '#/components/Identification'
import {
  ProgressIndicator,
  ProgressIndicatorSpinner,
} from '#/atoms/ProgressIndicator'

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
  pendingComponent: () => (
    <>
      {' '}
      <ProgressIndicator aria-labelledby="_r_24_" type="inlined">
        <ProgressIndicatorSpinner size="sm" />
        <span id="_r_24_">読み込み中</span>
      </ProgressIndicator>
    </>
  ),

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
      <IdentificationComponent />
      <Link to="/me">
        <div className="flex items-center justify-between w-full min-h-16 p-4 rounded-4 border-gray-400 border my-8">
          <p className="font-bold">プロフィールの変更</p>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="16"
            height="16"
            fill="currentColor"
            viewBox="0 0 16 16"
          >
            <path
              fill-rule="evenodd"
              d="M1 8a.5.5 0 0 1 .5-.5h11.793l-3.147-3.146a.5.5 0 0 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708-.708L13.293 8.5H1.5A.5.5 0 0 1 1 8"
            />
          </svg>
        </div>
      </Link>
      <Link to="/me/consents">
        <div className="flex items-center justify-between w-full min-h-16 p-4 rounded-4 border-gray-400 border my-8">
          <p className="font-bold">連携アプリケーションの管理</p>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="16"
            height="16"
            fill="currentColor"
            viewBox="0 0 16 16"
          >
            <path
              fill-rule="evenodd"
              d="M1 8a.5.5 0 0 1 .5-.5h11.793l-3.147-3.146a.5.5 0 0 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708-.708L13.293 8.5H1.5A.5.5 0 0 1 1 8"
            />
          </svg>
        </div>
      </Link>
      <Link to="/login">
        <div className="flex items-center justify-between w-full min-h-16 p-4 rounded-4 border-gray-400 border my-8">
          <p className="font-bold">別のアカウントでログイン</p>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="16"
            height="16"
            fill="currentColor"
            viewBox="0 0 16 16"
          >
            <path
              fill-rule="evenodd"
              d="M1 8a.5.5 0 0 1 .5-.5h11.793l-3.147-3.146a.5.5 0 0 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708-.708L13.293 8.5H1.5A.5.5 0 0 1 1 8"
            />
          </svg>
        </div>
      </Link>
      <Link to="/logout">
        <div className="flex items-center justify-between w-full min-h-16 p-4 rounded-4 border-gray-400 border my-8">
          <p className="font-bold">ログアウト</p>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            width="16"
            height="16"
            fill="currentColor"
            viewBox="0 0 16 16"
          >
            <path
              fill-rule="evenodd"
              d="M1 8a.5.5 0 0 1 .5-.5h11.793l-3.147-3.146a.5.5 0 0 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708-.708L13.293 8.5H1.5A.5.5 0 0 1 1 8"
            />
          </svg>
        </div>
      </Link>
    </div>
  )
}
