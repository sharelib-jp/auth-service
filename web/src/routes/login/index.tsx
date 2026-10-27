import { createFileRoute } from '@tanstack/react-router'
import { Button } from '#/components/Button'
import { Heading, HeadingTitle } from '#/components/Heading'
import { Divider } from '#/components/Divider'
import { Image, ImageArea } from '#/components/Image'
import { useState } from 'react'
import { ErrorText } from '#/components/ErrorText'
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
    return (
      <div>
        <Heading hasChip={false} size="36">
          <HeadingTitle level="h2">ログイン成功</HeadingTitle>
        </Heading>
        <div className="mt-[2em]">
          <p>ようこそ、{user.Name}さん！</p>
          <p>ユーザーID: {user.ID}</p>
          <p>ユーザー名: {user.UserName}</p>
        </div>
      </div>
    )
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
