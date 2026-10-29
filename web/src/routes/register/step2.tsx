import { createFileRoute, Navigate } from '@tanstack/react-router'
import { Heading, HeadingTitle } from '#/atoms/Heading'
import { Button } from '#/atoms/Button'
import { RegisterNavigation } from './-RegisterNavigation'
import { useRegistration } from './-RegisterContext'
import { Image, ImageArea } from '#/atoms/Image'
import success from '#/assets/smartphone-success.png'
import attention from '#/assets/smartphone-attention.png'
import placeholder from '#/assets/placeholder.png'
import { useState } from 'react'
import { validateRegistration } from './-validation'
import { ErrorText } from '#/atoms/ErrorText'

export const Route = createFileRoute('/register/step2')({
  component: RouteComponent,
})

function RouteComponent() {
  const { values } = useRegistration()

  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [isRegistrationComplete, setIsRegistrationComplete] = useState(false)
  const navigate = Route.useNavigate()

  if (Object.keys(validateRegistration(values)).length > 0) {
    return <Navigate to="/register/step1" replace={true} />
  }

  async function handleBeginRegistration() {
    if (isSubmitting) return

    setIsSubmitting(true)
    setSubmitError(null)
    setIsRegistrationComplete(false)

    try {
      const attributes: {
        gender: string
        birthDate?: string
      } = {
        gender: values.gender,
      }

      if (values.birthYear.trim() !== '') {
        attributes.birthDate = [
          values.birthYear.trim(),
          values.birthMonth.trim().padStart(2, '0'),
          values.birthDay.trim().padStart(2, '0'),
        ].join('-')
      }

      const requestBody = {
        UserName: values.accountName.trim(),
        Name: values.screenName.trim(),
        Email: values.email.trim(),
        attributes,
      }

      const response = await fetch('/api/auth/register/begin', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      })

      if (!response.ok) {
        setSubmitError(
          response.status === 409
            ? 'アカウント名またはメールアドレスはすでに登録されています'
            : '登録が正常に開始できませんでした。もう一度お試しください。',
        )
        return
      }

      const data: {
        publicKey: PublicKeyCredentialCreationOptionsJSON
      } = await response.json()

      const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
        data.publicKey,
      )

      const credential = await navigator.credentials.create({
        publicKey,
      })

      if (!(credential instanceof PublicKeyCredential)) {
        setSubmitError('パスキーを作成できませんでした。もう一度お試しください')
        return
      }

      const credentialJSON = credential.toJSON()

      const finishResponse = await fetch('/api/auth/register/finish', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(credentialJSON),
      })

      if (!finishResponse.ok) {
        setSubmitError('登録を完了できませんでした。もう一度お試しください')
        return
      }

      setIsRegistrationComplete(true)
    } catch (error) {
      if (error instanceof DOMException && error.name === 'NotAllowedError') {
        setSubmitError(
          'パスキーの作成が完了しなかったか、許可されませんでした。もう一度お試しください',
        )
      } else {
        setSubmitError(
          'パスキーの登録の処理に失敗しました。もう一度お試しください',
        )
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  if (submitError) {
    // パスキーの登録に失敗したとき
    return (
      <div>
        {' '}
        <Heading hasChip={false} size="36" className="mb-8">
          <HeadingTitle level="h2">パスキーの登録</HeadingTitle>
        </Heading>
        <div className="my-8 max-w-full">
          <RegisterNavigation currentStep={2} />
        </div>
        <Image fullWidth={true} className="mt-[2em]">
          <ImageArea bordered={false}>
            <img alt="" src={attention} />
          </ImageArea>
        </Image>
        <ErrorText role="alert" className="my-4">
          {submitError}
        </ErrorText>
        <Button
          disabled={isSubmitting}
          aria-disabled={isSubmitting}
          onClick={() => void handleBeginRegistration()}
          size="lg"
          variant="solid-fill"
          className="w-full"
        >
          再試行する
        </Button>
      </div>
    )
  }

  if (isRegistrationComplete) {
    // パスキーの登録に成功した時
    return (
      <div>
        {' '}
        <Heading hasChip={false} size="36" className="mb-8">
          <HeadingTitle level="h2">パスキーの登録</HeadingTitle>
        </Heading>
        <div className="my-8 max-w-full">
          <RegisterNavigation currentStep={2} />
        </div>
        <Image fullWidth={true} className="mt-[2em]">
          <ImageArea bordered={false}>
            <img alt="" src={success} />
          </ImageArea>
        </Image>
        <p className="my-4">パスキーの登録に成功しました</p>
        <Button
          disabled={isSubmitting}
          aria-disabled={isSubmitting}
          onClick={() =>
            void navigate({
              to: '/register/step3',
              replace: true,
            })
          }
          size="lg"
          variant="solid-fill"
          className="w-full"
        >
          次へ進む
        </Button>
      </div>
    )
  }

  return (
    <div>
      <Heading hasChip={false} size="36" className="mb-8">
        <HeadingTitle level="h2">パスキーの登録</HeadingTitle>
      </Heading>
      <div className="my-8 max-w-full">
        <RegisterNavigation currentStep={2} />
      </div>
      <Image fullWidth={true} className="mt-[2em]">
        <ImageArea bordered={false}>
          <img alt="" height="392" src={placeholder} width="696" />
        </ImageArea>
      </Image>

      {submitError && (
        <ErrorText role="alert" className="my-4">
          {submitError}
        </ErrorText>
      )}

      <Button
        disabled={isSubmitting}
        aria-disabled={isSubmitting}
        onClick={() => void handleBeginRegistration()}
        size="lg"
        variant="outline"
        className="w-full"
      >
        {isSubmitting ? '準備中' : 'パスキーを作成'}
      </Button>
    </div>
  )
}
