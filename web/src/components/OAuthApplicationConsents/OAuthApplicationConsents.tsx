import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Button } from '#/atoms/Button'
import { Heading, HeadingTitle } from '#/atoms/Heading'
import { List } from '#/atoms/List'
import {
  ResourceListContents,
  ResourceListSupport,
  ResourceListTitle,
} from '#/atoms/ResourceList'
import {
  ResourceListWithAccordion,
  ResourceListWithAccordionContent,
  ResourceListWithAccordionSummary,
} from '#/atoms/ResourceListWithAccordion'
import { Toast } from '#/atoms/Toast'

type Consent = {
  id: string
  client_id: string
  client_name: string
  resource_name: string
  scopes: Array<string>
  scope_descriptions: Record<string, string>
  status: string
  granted_at: string
  expires_at: string | null
}

const consentsKey = ['me', 'consents'] as const

async function fetchConsents(signal: AbortSignal): Promise<Array<Consent>> {
  const response = await fetch('/api/me/consents', {
    credentials: 'same-origin',
    signal,
  })
  if (!response.ok) throw new Error('同意一覧を取得できませんでした。')
  return (await response.json()) as Array<Consent>
}

function formatDate(value: string) {
  const date = new Date(value)
  return Number.isNaN(date.getTime())
    ? '日付不明'
    : new Intl.DateTimeFormat('ja-JP', { dateStyle: 'long' }).format(date)
}

export function OAuthApplicationConsents() {
  const queryClient = useQueryClient()
  const [notice, setNotice] = useState<{
    message: string
    variant: 'success' | 'error'
  } | null>(null)
  const { data, isPending, isError, refetch } = useQuery({
    queryKey: consentsKey,
    queryFn: ({ signal }) => fetchConsents(signal),
    retry: false,
    gcTime: 0,
  })
  const revoke = useMutation({
    mutationFn: async (id: string) => {
      const response = await fetch(
        `/api/me/consents/${encodeURIComponent(id)}`,
        {
          method: 'DELETE',
          credentials: 'same-origin',
        },
      )
      if (!response.ok) throw new Error('アクセス権を取り消せませんでした。')
      return id
    },
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: consentsKey })
    },
    onSuccess: (id) => {
      queryClient.setQueryData<Array<Consent>>(consentsKey, (current) =>
        current?.filter((grant) => grant.id !== id),
      )
      setNotice({ message: 'アクセス権を取り消しました。', variant: 'success' })
      void queryClient.invalidateQueries({ queryKey: consentsKey })
    },
    onError: () => {
      setNotice({
        message: 'アクセス権を取り消せませんでした。再度お試しください。',
        variant: 'error',
      })
      void queryClient.invalidateQueries({ queryKey: consentsKey })
    },
  })

  if (isPending) return <p role="status">同意一覧を読み込んでいます…</p>
  if (isError) {
    return (
      <div role="alert">
        <p>同意一覧を取得できませんでした。ログイン状態を確認してください。</p>
        <Button
          className="mt-4"
          type="button"
          size="md"
          variant="outline"
          onClick={() => void refetch()}
        >
          再読み込み
        </Button>
      </div>
    )
  }

  const active = data.filter(
    (grant) =>
      grant.status === 'active' &&
      (!grant.expires_at || new Date(grant.expires_at).getTime() > Date.now()),
  )
  const applications = new Map<
    string,
    { name: string; grants: Array<Consent> }
  >()
  for (const grant of active) {
    const application = applications.get(grant.client_id)
    if (application) application.grants.push(grant)
    else
      applications.set(grant.client_id, {
        name: grant.client_name,
        grants: [grant],
      })
  }

  return (
    <>
      {applications.size === 0 ? (
        <p>許可中のアプリケーションはありません。</p>
      ) : (
        <ul className="grid gap-4">
          {Array.from(applications, ([clientId, application]) => (
            <li key={clientId}>
              <ResourceListWithAccordion variant="frame">
                <ResourceListWithAccordionSummary>
                  <ResourceListContents>
                    <ResourceListTitle as="h3">
                      {application.name}
                    </ResourceListTitle>
                    <ResourceListSupport>
                      許可したアクセス権：{application.grants.length}件
                    </ResourceListSupport>
                  </ResourceListContents>
                </ResourceListWithAccordionSummary>
                <ResourceListWithAccordionContent>
                  <Heading hasChip={false} size="18">
                    <HeadingTitle level="h4">
                      許可したアクセス権の一覧
                    </HeadingTitle>
                  </Heading>
                  <List spacing="4" className="my-4 w-full">
                    {application.grants.map((grant) => (
                      <li key={grant.id}>
                        <p>
                          {grant.scopes
                            .map(
                              (scope) =>
                                grant.scope_descriptions[scope] || scope,
                            )
                            .join('、')}
                        </p>
                        <p className="text-sm">
                          提供元：{grant.resource_name} ／{' '}
                          {formatDate(grant.granted_at)}に許可
                        </p>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          className="my-2 disabled:opacity-50"
                          aria-label={`${application.name}の${grant.scopes.map((scope) => grant.scope_descriptions[scope] || scope).join('、')}のアクセス権を取り消す`}
                          disabled={revoke.isPending}
                          onClick={() => {
                            if (
                              window.confirm(
                                `「${application.name}」のこのアクセス権を取り消しますか？関連するアクセストークンも無効になります。`,
                              )
                            ) {
                              setNotice(null)
                              revoke.mutate(grant.id)
                            }
                          }}
                        >
                          {revoke.isPending && revoke.variables === grant.id
                            ? '取り消し中'
                            : 'このアクセス権を取り消す'}
                        </Button>
                      </li>
                    ))}
                  </List>
                </ResourceListWithAccordionContent>
              </ResourceListWithAccordion>
            </li>
          ))}
        </ul>
      )}
      {notice && (
        <Toast
          key={`${notice.variant}-${notice.message}`}
          {...notice}
          onClose={() => setNotice(null)}
        />
      )}
    </>
  )
}
