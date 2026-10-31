import { useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { Navigate, createFileRoute } from '@tanstack/react-router'
import { Button } from '#/atoms/Button'
import { ErrorText } from '#/atoms/ErrorText'
import { Heading, HeadingTitle } from '#/atoms/Heading'
import { logout } from '#/lib/logout'
import {
  ProgressIndicator,
  ProgressIndicatorSpinner,
} from '#/atoms/ProgressIndicator'

export const Route = createFileRoute('/logout/')({
  component: LogoutPage,
})

type LogoutState = 'pending' | 'success' | 'error'

function LogoutPage() {
  const queryClient = useQueryClient()
  const [state, setState] = useState<LogoutState>('pending')
  const started = useRef(false)
  const inFlight = useRef(false)

  async function handleLogout() {
    if (inFlight.current) return
    inFlight.current = true
    setState('pending')
    try {
      await logout()
      queryClient.clear()
      setState('success')
    } catch {
      setState('error')
    } finally {
      inFlight.current = false
    }
  }

  useEffect(() => {
    if (started.current) return
    started.current = true
    void handleLogout()
  }, [])

  return (
    <div>
      <Heading hasChip={false} size="36">
        <HeadingTitle level="h1">ログアウト</HeadingTitle>
      </Heading>
      {state === 'pending' && (
        <ProgressIndicator aria-labelledby="_r_v5_" type="stacked">
          <ProgressIndicatorSpinner size="lg" />
          <span id="_r_v5_">ログアウトしています</span>
        </ProgressIndicator>
      )}
      {state === 'success' && <Navigate to="/login" replace />}
      {state === 'error' && (
        <div className="mt-8">
          <ErrorText role="alert">
            ログアウトに失敗しました。もう一度お試しください。
          </ErrorText>
          <Button
            type="button"
            size="md"
            variant="outline"
            className="mt-6"
            onClick={() => void handleLogout()}
          >
            再試行
          </Button>
        </div>
      )}
    </div>
  )
}
