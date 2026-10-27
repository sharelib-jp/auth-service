export type RegistrationValues = {
  screenName: string
  accountName: string
  email: string
  birthYear: string
  birthMonth: string
  birthDay: string
  gender: string
}

export const registrationFields = [
  'screenName',
  'accountName',
  'email',
  'birthDate',
  'gender',
] as const

export type RegistrationField = (typeof registrationFields)[number]
export type RegistrationErrors = Partial<Record<RegistrationField, string>>

const emailPattern =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/i

function validateBirthDate(values: RegistrationValues, today: Date) {
  const parts = [values.birthYear, values.birthMonth, values.birthDay].map(
    (value) => value.trim(),
  )
  if (parts.every((part) => part === '')) return undefined
  if (parts.some((part) => part === '')) {
    return '生年月日は年・月・日をすべて入力してください。'
  }

  const [yearText, monthText, dayText] = parts
  if (
    !/^\d{4}$/.test(yearText) ||
    !/^\d{1,2}$/.test(monthText) ||
    !/^\d{1,2}$/.test(dayText)
  ) {
    return '年は西暦4桁、月・日は1〜2桁の半角数字で入力してください。'
  }

  const [year, month, day] = parts.map(Number)
  const isLeapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)
  const daysInMonth = [
    31,
    isLeapYear ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ]
  if (
    year < 1 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > daysInMonth[month - 1]
  ) {
    return '実在する日付を入力してください。'
  }

  const birthDate = year * 10000 + month * 100 + day
  const currentDate =
    today.getFullYear() * 10000 + (today.getMonth() + 1) * 100 + today.getDate()
  if (birthDate > currentDate) {
    return '生年月日には今日以前の日付を入力してください。'
  }

  return undefined
}

export function validateRegistration(
  values: RegistrationValues,
  today = new Date(),
): RegistrationErrors {
  const errors: RegistrationErrors = {}
  const screenName = values.screenName.trim()
  const accountName = values.accountName.trim()
  const email = values.email.trim()

  if (!screenName) {
    errors.screenName = '表示名を入力してください。'
  } else if ([...screenName].length > 100) {
    errors.screenName = '表示名は100文字以内で入力してください。'
  } else if (/\p{Cc}/u.test(screenName)) {
    errors.screenName = '表示名には改行や制御文字を使用できません。'
  }

  if (!accountName) {
    errors.accountName = 'アカウント名を入力してください。'
  } else if (accountName.length > 64) {
    errors.accountName = 'アカウント名は64文字以内で入力してください。'
  } else if (!/^[a-z0-9_]+$/.test(accountName)) {
    errors.accountName =
      'アカウント名は半角英小文字・数字・_（アンダースコア）のみで入力してください。'
  }

  if (!email) {
    errors.email = 'メールアドレスを入力してください。'
  } else if ([...email].length > 254) {
    errors.email = 'メールアドレスは254文字以内で入力してください。'
  } else if (!emailPattern.test(email)) {
    errors.email = 'メールアドレスをuser@example.comの形式で入力してください。'
  }

  const birthDateError = validateBirthDate(values, today)
  if (birthDateError) errors.birthDate = birthDateError

  if (!['m', 'w', 'na'].includes(values.gender)) {
    errors.gender =
      '性別を選択してください。回答しない場合は「未回答・その他」を選択してください。'
  }

  return errors
}
