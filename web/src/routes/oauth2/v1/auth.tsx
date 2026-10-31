import { useEffect, useState } from 'react'
import { createFileRoute } from '@tanstack/react-router'
import { Button } from '#/atoms/Button'
import { Heading, HeadingTitle } from '#/atoms/Heading'
import {
  NotificationBanner,
  NotificationBannerBody,
} from '#/atoms/NotificationBanner'

export const Route = createFileRoute('/oauth2/v1/auth')({
  validateSearch: (search: Record<string, unknown>) => ({
    request:
      typeof search.request === 'string' &&
      /^[A-Za-z0-9_-]{43}$/.test(search.request)
        ? search.request
        : undefined,
  }),
  component: AuthorizationPage,
})

type ConsentDetails = {
  client_name: string
  user_name: string
  user_email: string
  csrf: string
  offline_access: boolean
  scopes: Array<{
    name: string
    description: string
    purpose: string
    resource: string
    already_granted: boolean
  }>
}

type LoadState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; details: ConsentDetails }

function AuthorizationPage() {
  const { request } = Route.useSearch()
  const [state, setState] = useState<LoadState>({ status: 'loading' })

  useEffect(() => {
    if (!request) {
      setState({
        status: 'error',
        message: '認可リクエストが正しくありません。',
      })
      return
    }

    const controller = new AbortController()
    setState({ status: 'loading' })

    async function loadConsent() {
      try {
        const response = await fetch(
          `/api/oauth2/consent?request=${encodeURIComponent(request!)}`,
          {
            credentials: 'same-origin',
            referrerPolicy: 'no-referrer',
            signal: controller.signal,
          },
        )
        if (response.status === 401) {
          window.location.replace(
            `/login/?oauth_request=${encodeURIComponent(request!)}`,
          )
          return
        }
        if (!response.ok) {
          setState({
            status: 'error',
            message:
              response.status === 400
                ? '認可リクエストを確認できませんでした。有効期限が切れている場合は、アプリケーションからやり直してください。'
                : '認可リクエストを読み込めませんでした。再度お試しください。',
          })
          return
        }
        const details = (await response.json()) as ConsentDetails
        if (
          typeof details.client_name !== 'string' ||
          typeof details.user_name !== 'string' ||
          typeof details.user_email !== 'string' ||
          typeof details.csrf !== 'string' ||
          !/^[A-Za-z0-9_-]{43}$/.test(details.csrf) ||
          typeof details.offline_access !== 'boolean' ||
          !Array.isArray(details.scopes) ||
          !details.scopes.every(
            (scope) =>
              typeof scope.name === 'string' &&
              typeof scope.description === 'string' &&
              typeof scope.purpose === 'string' &&
              typeof scope.resource === 'string' &&
              typeof scope.already_granted === 'boolean',
          )
        ) {
          throw new Error('Invalid consent response')
        }
        setState({ status: 'ready', details })
      } catch {
        if (!controller.signal.aborted) {
          setState({
            status: 'error',
            message:
              '認可リクエストを読み込めませんでした。再度お試しください。',
          })
        }
      }
    }

    void loadConsent()
    return () => controller.abort()
  }, [request])

  if (state.status === 'loading') {
    return <p role="status">認可リクエストを確認しています…</p>
  }

  if (state.status === 'error' || !request) {
    return (
      <div role="alert">
        <Heading size="28" hasChip={false}>
          <HeadingTitle level="h1">アクセス許可を確認できません</HeadingTitle>
        </Heading>
        <p className="mt-4">
          {state.status === 'error'
            ? state.message
            : '認可リクエストが正しくありません。'}
        </p>
      </div>
    )
  }

  const { details } = state
  return (
    <section className="my-8 rounded-4 border border-gray-400 p-6 sm:p-12">
      <Heading size="28" hasChip={false}>
        <HeadingTitle level="h1">アクセス許可の確認</HeadingTitle>
      </Heading>
      <p className="mt-6">
        <strong>{details.client_name}</strong>
        があなたの情報へのアクセスを求めています。
      </p>
      <p className="mt-4">
        ログイン中のアカウント：{details.user_name}（{details.user_email}）
      </p>

      {details.scopes.length > 0 ? (
        <>
          <h2 className="mt-8 text-xl font-bold">要求されている権限</h2>
          <ul className="mt-4 list-disc space-y-4 pl-6">
            {details.scopes.map((scope) => (
              <li key={scope.name}>
                <strong>{scope.description}</strong>
                <p className="text-sm">
                  提供元：{scope.resource} ／ 利用目的：{scope.purpose}
                  {scope.already_granted && ' ／ 許可済み'}
                </p>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-sm">権限はまとめて許可または拒否します。</p>
        </>
      ) : (
        <p className="mt-6">
          このアプリケーションへのログインを確認してください。
        </p>
      )}

      {details.offline_access && (
        <NotificationBanner
          bannerStyle="standard"
          className="my-6"
          headingLevel="h2"
          title="継続的なアクセスについて"
          type="warning"
        >
          <NotificationBannerBody>
            <p>
              このアプリケーションは、利用していない間も許可された情報にアクセスできます。
            </p>
          </NotificationBannerBody>
        </NotificationBanner>
      )}

      <form
        method="post"
        action="/api/oauth2/consent"
        className="mt-8 flex flex-wrap justify-between gap-4"
      >
        <input type="hidden" name="request" value={request} />
        <input type="hidden" name="csrf" value={details.csrf} />
        <Button
          type="submit"
          name="decision"
          value="deny"
          size="md"
          variant="outline"
        >
          許可しない
        </Button>
        <Button
          type="submit"
          name="decision"
          value="allow"
          size="md"
          variant="solid-fill"
        >
          許可する
        </Button>
      </form>
    </section>
  )
}
