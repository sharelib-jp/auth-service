import { createFileRoute } from '@tanstack/react-router'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { RegisterNavigation } from './-RegisterNavigation'
import { useRegistration } from './-RegisterContext'
import { registrationFields, validateRegistration } from './-validation'
import type {
  RegistrationErrors,
  RegistrationField,
  RegistrationValues,
} from './-validation'
import { Heading, HeadingTitle } from '#/atoms/Heading'
import { Divider } from '#/atoms/Divider'
import {
  FormControlLabel,
  Label,
  RequirementBadge,
  SupportText,
  Legend,
} from '#/atoms/FormControlLabel'
import { Input } from '#/atoms/Input'
import {
  DatePicker,
  DatePickerYear,
  DatePickerMonth,
  DatePickerDate,
} from '#/atoms/DatePicker'
import { Radio } from '#/atoms/Radio'
import { Button } from '#/atoms/Button'
import { ErrorText } from '#/atoms/ErrorText'

export const Route = createFileRoute('/register/step1')({
  component: RouteComponent,
})

function RouteComponent() {
  const { values, setValues } = useRegistration()
  const [touched, setTouched] = useState<
    Partial<Record<RegistrationField, boolean>>
  >({})
  const [hasSubmitted, setHasSubmitted] = useState(false)
  const [isValidationComplete, setIsValidationComplete] = useState(false)
  const errors = validateRegistration(values)
  const visibleErrors: RegistrationErrors = {}
  for (const field of registrationFields) {
    if (hasSubmitted || touched[field]) visibleErrors[field] = errors[field]
  }
  const errorCount = Object.keys(errors).length
  const navigate = Route.useNavigate()

  function updateValue(field: keyof RegistrationValues, value: string) {
    setValues((current) => ({ ...current, [field]: value }))
    setIsValidationComplete(false)
  }

  function touchField(field: RegistrationField) {
    setTouched((current) => ({ ...current, [field]: true }))
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setHasSubmitted(true)
    setIsValidationComplete(errorCount === 0)

    if (errorCount > 0) {
      const form = event.currentTarget
      requestAnimationFrame(() => {
        form
          .querySelector<HTMLInputElement>('input[aria-invalid="true"]')
          ?.focus()
      })

      return
    }

    void navigate({ to: '/register/step2' })
  }

  return (
    <form noValidate onSubmit={handleSubmit}>
      <Heading hasChip={false} size="36">
        <HeadingTitle level="h2">新規登録</HeadingTitle>
      </Heading>
      <div className="my-8 max-w-full">
        <RegisterNavigation currentStep={1} />
      </div>
      <Divider className="my-8" color="gray-536" />
      <div role="status" aria-atomic="true">
        {hasSubmitted && errorCount > 0 && (
          <ErrorText className="mb-4">
            入力内容に{errorCount}
            件のエラーがあります。各項目を確認してください。
          </ErrorText>
        )}
      </div>
      <p className="mb-4">
        利用者登録のために、以下の情報を入力してください。この情報はプライバシーポリシーを元に、サービスの提供のために利用されます。
      </p>
      <FormControlLabel className="mb-8">
        <Label htmlFor="screen_name">
          表示名
          <RequirementBadge>※必須</RequirementBadge>
        </Label>
        <SupportText id="screen_name-support">
          入力した名前は公開されます。後から変更できます。100文字以内で入力してください。
        </SupportText>
        <div>
          <Input
            aria-describedby={`screen_name-support${visibleErrors.screenName ? ' screen_name-error' : ''}`}
            blockSize="lg"
            autoComplete="nickname"
            id="screen_name"
            isError={Boolean(visibleErrors.screenName)}
            name="screen_name"
            required
            value={values.screenName}
            onChange={(event) => updateValue('screenName', event.target.value)}
            onBlur={() => touchField('screenName')}
            className="w-full"
          />
        </div>
        {visibleErrors.screenName && (
          <ErrorText id="screen_name-error" aria-live="polite">
            {visibleErrors.screenName}
          </ErrorText>
        )}
      </FormControlLabel>
      <FormControlLabel className="mb-8">
        <Label htmlFor="account_name">
          アカウント名
          <RequirementBadge>※必須</RequirementBadge>
        </Label>
        <SupportText id="account_name-support">
          アカウントを識別するために利用されます。後で変更できません。a-z、0-9、_（アンダースコア）のみ、64文字以内で入力してください。
        </SupportText>
        <div>
          <Input
            aria-describedby={`account_name-support${visibleErrors.accountName ? ' account_name-error' : ''}`}
            blockSize="lg"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            id="account_name"
            isError={Boolean(visibleErrors.accountName)}
            name="account_name"
            required
            value={values.accountName}
            onChange={(event) => updateValue('accountName', event.target.value)}
            onBlur={() => touchField('accountName')}
            className="w-full"
          />
        </div>
        {visibleErrors.accountName && (
          <ErrorText id="account_name-error" aria-live="polite">
            {visibleErrors.accountName}
          </ErrorText>
        )}
      </FormControlLabel>
      <FormControlLabel className="mb-8">
        <Label htmlFor="account_email">
          メールアドレス
          <RequirementBadge>※必須</RequirementBadge>
        </Label>
        <SupportText id="account_email-support">
          通知を受け取るために利用します。254文字以内で入力してください。
        </SupportText>
        <div>
          <Input
            aria-describedby={`account_email-support${visibleErrors.email ? ' account_email-error' : ''}`}
            blockSize="lg"
            type="email"
            autoComplete="email"
            autoCapitalize="none"
            spellCheck={false}
            id="account_email"
            isError={Boolean(visibleErrors.email)}
            name="account_email"
            required
            value={values.email}
            onChange={(event) => updateValue('email', event.target.value)}
            onBlur={() => touchField('email')}
            className="w-full"
          />
        </div>
        {visibleErrors.email && (
          <ErrorText id="account_email-error" aria-live="polite">
            {visibleErrors.email}
          </ErrorText>
        )}
      </FormControlLabel>
      <Divider className="my-8" color="gray-536" />
      <p className="mb-4">
        以下の属性情報は、運営主体が一部サービスの提供をするのに使われるほか、匿名化した統計情報の作成にも利用します。この情報はプライバシーポリシーを元に利用されます。
      </p>
      <FormControlLabel
        as="fieldset"
        aria-describedby={`date-support${visibleErrors.birthDate ? ' date-error' : ''}`}
        className="mb-8"
        onBlur={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget)) {
            touchField('birthDate')
          }
        }}
      >
        <Legend>
          <span>生年月日</span>
          <RequirementBadge isOptional>任意</RequirementBadge>
        </Legend>
        <SupportText id="date-support">
          任意です。入力する場合は、年（西暦4桁）・月・日を半角数字で入力してください。
        </SupportText>
        <div className="min-w-0 [grid-area:field]">
          <DatePicker size="md" isError={Boolean(visibleErrors.birthDate)}>
            {({ yearRef, monthRef, dateRef, ...rest }) => (
              <>
                <DatePickerYear
                  ref={yearRef}
                  {...rest}
                  id="birth_year"
                  name="birth_year"
                  aria-label="生年月日の年"
                  autoComplete="bday-year"
                  aria-describedby={`date-support${visibleErrors.birthDate ? ' date-error' : ''}`}
                  value={values.birthYear}
                  onChange={(event) =>
                    updateValue('birthYear', event.target.value)
                  }
                />
                <DatePickerMonth
                  ref={monthRef}
                  {...rest}
                  id="birth_month"
                  name="birth_month"
                  aria-label="生年月日の月"
                  autoComplete="bday-month"
                  aria-describedby={`date-support${visibleErrors.birthDate ? ' date-error' : ''}`}
                  value={values.birthMonth}
                  onChange={(event) =>
                    updateValue('birthMonth', event.target.value)
                  }
                />
                <DatePickerDate
                  ref={dateRef}
                  {...rest}
                  id="birth_day"
                  name="birth_day"
                  aria-label="生年月日の日"
                  autoComplete="bday-day"
                  aria-describedby={`date-support${visibleErrors.birthDate ? ' date-error' : ''}`}
                  value={values.birthDay}
                  onChange={(event) =>
                    updateValue('birthDay', event.target.value)
                  }
                />
              </>
            )}
          </DatePicker>
        </div>
        {visibleErrors.birthDate && (
          <ErrorText id="date-error" aria-live="polite">
            {visibleErrors.birthDate}
          </ErrorText>
        )}
      </FormControlLabel>
      <FormControlLabel
        as="fieldset"
        className="mb-8"
        aria-describedby={`gender-support${visibleErrors.gender ? ' gender-error' : ''}`}
        onBlur={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget)) {
            touchField('gender')
          }
        }}
      >
        <Legend>
          性別
          <RequirementBadge>※必須</RequirementBadge>
        </Legend>
        <SupportText id="gender-support">
          性別を選択してください。回答しない場合は「未回答・その他」を選択してください。
        </SupportText>
        <div className="flex flex-wrap gap-x-4">
          {[
            { value: 'm', label: '男性' },
            { value: 'w', label: '女性' },
            { value: 'na', label: '未回答・その他' },
          ].map(({ value, label }) => (
            <Radio
              key={value}
              aria-describedby={`gender-support${visibleErrors.gender ? ' gender-error' : ''}`}
              aria-invalid={Boolean(visibleErrors.gender)}
              isError={Boolean(visibleErrors.gender)}
              name="gender"
              value={value}
              required
              checked={values.gender === value}
              onChange={(event) => updateValue('gender', event.target.value)}
              size="sm"
            >
              {label}
            </Radio>
          ))}
        </div>
        {visibleErrors.gender && (
          <ErrorText id="gender-error" aria-live="polite">
            {visibleErrors.gender}
          </ErrorText>
        )}
      </FormControlLabel>
      <div role="status" aria-atomic="true">
        {isValidationComplete && (
          <p className="mb-4">入力内容のチェックが完了しました。</p>
        )}
      </div>
      <Button type="submit" size="lg" variant="outline" className="w-full">
        新規登録
      </Button>
    </form>
  )
}
