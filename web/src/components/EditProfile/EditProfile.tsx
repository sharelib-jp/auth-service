import { useId, useState } from 'react'
import type { FormEvent } from 'react'
import { Button } from '#/atoms/Button'
import { ErrorText } from '#/atoms/ErrorText'
import {
  FormControlLabel,
  Label,
  RequirementBadge,
  SupportText,
} from '#/atoms/FormControlLabel'
import { Input } from '#/atoms/Input'
import { Toast } from '#/atoms/Toast'
import type { ToastVariant } from '#/atoms/Toast'
import {
  useMe,
  usePatchMeEmail,
  usePatchMeName,
  usePatchMeUserName,
} from '#/lib/useMe'
import type { Me } from '#/lib/useMe'
import { validateRegistration } from '#/lib/validateInputText'

const horizontalLayout = `
  [overflow-wrap:anywhere]
  md:grid md:[grid-template:'label_field_field'_auto_'support-text_field_field'_1fr_/_1fr_1fr_1fr] md:gap-x-6 md:justify-start md:items-baseline
  md:[&>label]:self-baseline md:[&>label]:[grid-area:label]
  md:[&>p]:[grid-area:support-text]
`

export const EditProfileComponent = () => {
  const { data: me, isPending, isError, refetch } = useMe()

  if (isPending) return <p role="status">読み込み中</p>
  if (isError) {
    return (
      <div role="alert">
        <p>ユーザー情報の取得に失敗しました。</p>
        <Button size="md" variant="outline" onClick={() => void refetch()}>
          再読み込み
        </Button>
      </div>
    )
  }
  return <EditProfileForm me={me} />
}

function EditProfileForm({ me }: { me: Me }) {
  const id = useId()
  const [values, setValues] = useState({
    screenName: me.Name,
    accountName: me.UserName,
    email: me.Email,
  })
  const [submitted, setSubmitted] = useState(false)
  const [saving, setSaving] = useState(false)
  const [toast, setToast] = useState<{
    id: number
    message: string
    variant: ToastVariant
  } | null>(null)
  const [toastId, setToastId] = useState(0)

  function showToast(message: string, variant: ToastVariant) {
    const nextId = toastId + 1
    setToastId(nextId)
    setToast({ id: nextId, message, variant })
  }
  const nameMutation = usePatchMeName()
  const userNameMutation = usePatchMeUserName()
  const emailMutation = usePatchMeEmail()
  const errors = validateRegistration({
    ...values,
    birthYear: '',
    birthMonth: '',
    birthDay: '',
    gender: 'na',
  })

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setSubmitted(true)
    setToast(null)
    if (errors.screenName || errors.accountName || errors.email || saving)
      return

    setSaving(true)
    try {
      if (values.screenName.trim() !== me.Name)
        await nameMutation.mutateAsync(values.screenName.trim())
      if (values.accountName.trim() !== me.UserName)
        await userNameMutation.mutateAsync(values.accountName.trim())
      if (values.email.trim() !== me.Email)
        await emailMutation.mutateAsync(values.email.trim())
      showToast('プロフィールを保存しました。', 'success')
    } catch (error) {
      showToast(
        error instanceof Error ? error.message : '更新に失敗しました。',
        'error',
      )
    } finally {
      setSaving(false)
    }
  }

  const fields = [
    {
      key: 'screenName',
      label: '表示名',
      support: '100文字以内で入力してください。',
      autoComplete: 'nickname',
    },
    {
      key: 'accountName',
      label: 'ユーザ名',
      support: '半角英小文字・数字・_のみ、64文字以内で入力してください。',
      autoComplete: 'username',
    },
    {
      key: 'email',
      label: 'メールアドレス',
      support: '254文字以内で入力してください。',
      autoComplete: 'email',
    },
  ] as const

  return (
    <form noValidate onSubmit={(event) => void handleSubmit(event)}>
      <div className="grid gap-y-8">
        {fields.map(({ key, label, support, autoComplete }) => {
          const inputId = `${id}-${key}`
          const error = submitted ? errors[key] : undefined
          return (
            <FormControlLabel key={key} className={horizontalLayout}>
              <Label htmlFor={inputId}>
                {label}
                <RequirementBadge>※必須</RequirementBadge>
              </Label>
              <SupportText id={`${inputId}-support`}>{support}</SupportText>
              <div className="min-w-0 [grid-area:field]">
                <Input
                  id={inputId}
                  className="w-full"
                  name={key}
                  type={key === 'email' ? 'email' : 'text'}
                  autoComplete={autoComplete}
                  blockSize="md"
                  required
                  disabled={saving}
                  value={values[key]}
                  onChange={(event) => {
                    setValues((current) => ({
                      ...current,
                      [key]: event.target.value,
                    }))
                  }}
                  isError={Boolean(error)}
                  aria-describedby={`${inputId}-support${error ? ` ${inputId}-error` : ''}`}
                />
                {error && (
                  <ErrorText className="mt-2" id={`${inputId}-error`}>
                    {error}
                  </ErrorText>
                )}
              </div>
            </FormControlLabel>
          )
        })}
      </div>
      {toast && (
        <Toast
          key={toast.id}
          message={toast.message}
          variant={toast.variant}
          onClose={() => setToast(null)}
        />
      )}
      <Button
        className="mt-8 w-full"
        type="submit"
        size="md"
        variant="solid-fill"
        disabled={saving}
      >
        {saving ? '保存中' : '保存'}
      </Button>
    </form>
  )
}
