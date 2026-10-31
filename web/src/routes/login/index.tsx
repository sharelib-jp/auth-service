import { Navigate, createFileRoute } from '@tanstack/react-router'
import { Button } from '#/atoms/Button'
import { Heading, HeadingTitle } from '#/atoms/Heading'
import { Divider } from '#/atoms/Divider'
import { Image, ImageArea } from '#/atoms/Image'
import { useEffect, useState } from 'react'
import { ErrorText } from '#/atoms/ErrorText'
import placeholder from '#/assets/placeholder.png'

export const Route = createFileRoute('/login/')({
  component: LoginPageComponent,
})

type LoginUser = {
  ID: string
  UserName: string
  Name: string
}

function LoginPageComponent() {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [user, setUser] = useState<LoginUser | null>(null)

  const pendingRequest = new URLSearchParams(window.location.search).get(
    'oauth_request',
  )
  const oauthRequest =
    pendingRequest && /^[A-Za-z0-9_-]{43}$/.test(pendingRequest)
      ? pendingRequest
      : null

  useEffect(() => {
    if (!oauthRequest) return
    const controller = new AbortController()
    void fetch('/api/auth/oauth-session', {
      credentials: 'same-origin',
      signal: controller.signal,
    })
      .then((response) => {
        if (response.ok) {
          window.location.replace(
            `/api/oauth2/continue?request=${oauthRequest}`,
          )
        }
      })
      .catch(() => {})
    return () => controller.abort()
  }, [oauthRequest])

  async function handleLogin() {
    if (isSubmitting) {
      return
    }

    setIsSubmitting(true)
    setSubmitError(null)

    try {
      const response = await fetch('/api/auth/login/begin', {
        method: 'POST',
        credentials: 'same-origin',
      })

      if (!response.ok) {
        setSubmitError('ログインに失敗しました。再度お試しください')
        return
      }

      const data: {
        publicKey: PublicKeyCredentialRequestOptionsJSON
      } = await response.json()

      const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
        data.publicKey,
      )
      const credential = await navigator.credentials.get({ publicKey })

      if (!(credential instanceof PublicKeyCredential)) {
        setSubmitError('ログインに失敗しました。再度お試しください')
        return
      }

      const credentialJSON = credential.toJSON()

      const finishResponse = await fetch('/api/auth/login/finish', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentialJSON),
      })

      if (!finishResponse.ok) {
        setSubmitError('ログインに失敗しました。再度お試しください')
        return
      }

      const loggedInUser: LoginUser = await finishResponse.json()
      if (oauthRequest) {
        window.location.replace(`/api/oauth2/continue?request=${oauthRequest}`)
        return
      }
      setUser(loggedInUser)
    } catch (error) {
      console.error(error)

      if (error instanceof DOMException && error.name === 'NotAllowedError') {
        setSubmitError('ログインがキャンセルされました。再度お試しください')
      } else {
        setSubmitError('ログインに失敗しました。再度お試しください')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  if (user) {
    return <Navigate to="/" replace />
  }

  return (
    <div>
      <Heading hasChip={false} size="36">
        <HeadingTitle level="h2">ログイン</HeadingTitle>
      </Heading>
      <Image fullWidth={true} className="mt-[2em]">
        <ImageArea bordered={false}>
          <img alt="" height="392" src={placeholder} width="696" />
        </ImageArea>
      </Image>
      <div className="mt-[2em]">
        {submitError && (
          <ErrorText role="alert" className="mb-4">
            {submitError}
          </ErrorText>
        )}
        <Button
          type="button"
          disabled={isSubmitting}
          aria-disabled={isSubmitting}
          onClick={() => void handleLogin()}
          size="lg"
          variant="solid-fill"
          className="w-full"
        >
          {isSubmitting ? 'ログイン中...' : 'パスキーでログイン'}
        </Button>
      </div>
      <Divider className="my-[1em]" color="gray-536" />
      <div>
        <a href="/register/step1">
          <Button
            aria-disabled={false}
            onClick={() => {}}
            size="lg"
            variant="outline"
            className="w-full"
          >
            新規登録
          </Button>
        </a>
      </div>
    </div>
  )
}
