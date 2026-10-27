import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { validateRegistration } from '../src/routes/register/-validation.ts'

const today = new Date(2026, 9, 25, 12)
const validValues = {
  screenName: 'ももたろう',
  accountName: 'momotaro_123',
  email: 'user@example.com',
  birthYear: '',
  birthMonth: '',
  birthDay: '',
  gender: 'na',
}

function validate(overrides = {}) {
  return validateRegistration({ ...validValues, ...overrides }, today)
}

describe('登録フォームの入力チェック', () => {
  it('任意の生年月日が空欄でも正常に入力できる', () => {
    assert.deepEqual(validate(), {})
  })

  it('未入力の必須項目をすべて報告する', () => {
    const errors = validate({
      screenName: '',
      accountName: '',
      email: '',
      gender: '',
    })
    assert.deepEqual(Object.keys(errors), [
      'screenName',
      'accountName',
      'email',
      'gender',
    ])
    assert.match(errors.screenName, /入力してください/)
    assert.match(errors.accountName, /入力してください/)
    assert.match(errors.email, /入力してください/)
    assert.match(errors.gender, /選択してください/)
  })

  it('空白のみの必須項目は未入力として扱う', () => {
    const errors = validate({
      screenName: '　 ',
      accountName: ' ',
      email: '\t ',
    })
    assert.deepEqual(Object.keys(errors), [
      'screenName',
      'accountName',
      'email',
    ])
  })

  it('APIと同様に前後の空白を除いて検証し、入力値自体は変更しない', () => {
    const values = {
      ...validValues,
      screenName: '  ももたろう　',
      accountName: ' momotaro_123 ',
      email: ' User+news@Example.COM ',
    }
    assert.deepEqual(validateRegistration(values, today), {})
    assert.equal(values.email, ' User+news@Example.COM ')
  })

  it('表示名はUnicodeの文字数で100文字まで許可する', () => {
    assert.equal(
      validate({ screenName: '🍑'.repeat(100) }).screenName,
      undefined,
    )
    assert.match(
      validate({ screenName: '🍑'.repeat(101) }).screenName,
      /100文字/,
    )
  })

  it('表示名に含まれる制御文字を拒否する', () => {
    for (const control of ['\n', '\t', '\u0000', '\u0085']) {
      assert.match(
        validate({ screenName: `名前${control}です` }).screenName,
        /制御文字/,
      )
    }
  })

  it('アカウント名は64文字まで許可する', () => {
    assert.equal(
      validate({ accountName: 'a'.repeat(64) }).accountName,
      undefined,
    )
    assert.match(
      validate({ accountName: 'a'.repeat(65) }).accountName,
      /64文字/,
    )
  })

  for (const accountName of [
    'Momotaro',
    'momo-taro',
    'momo taro',
    'もも',
    'ｍｏｍｏ',
  ]) {
    it(`アカウント名「${accountName}」の使用できない文字を拒否する`, () => {
      assert.match(validate({ accountName }).accountName, /半角英小文字/)
    })
  }

  it('メールアドレスのプラス記号やサブドメインを許可する', () => {
    assert.equal(
      validate({ email: 'User.Name+news@mail.example.co.jp' }).email,
      undefined,
    )
  })

  for (const email of [
    'user',
    '@example.com',
    'user@',
    'user@@example.com',
    'user name@example.com',
    'user..name@example.com',
    '.user@example.com',
    'user.@example.com',
    'user@-example.com',
    'user@example..com',
    'user@example.com.',
    'User <user@example.com>',
    'user@example.com\nother@example.com',
  ]) {
    it(`メールアドレス ${JSON.stringify(email)} の形式エラーを報告する`, () => {
      assert.match(validate({ email }).email, /形式/)
    })
  }

  it('メールアドレスは254文字まで許可する', () => {
    assert.equal(
      validate({ email: `${'a'.repeat(242)}@example.com` }).email,
      undefined,
    )
    assert.match(
      validate({ email: `${'a'.repeat(243)}@example.com` }).email,
      /254文字/,
    )
  })

  for (const gender of ['m', 'w', 'na']) {
    it(`性別の選択値「${gender}」を受け付ける`, () => {
      assert.equal(validate({ gender }).gender, undefined)
    })
  }

  it('性別の不正な選択値を拒否する', () => {
    assert.match(validate({ gender: 'invalid' }).gender, /選択してください/)
  })
})

describe('生年月日の入力チェック', () => {
  for (const parts of [
    { birthYear: '2000' },
    { birthMonth: '1', birthDay: '1' },
    { birthYear: '2000', birthMonth: '1' },
  ]) {
    it(`一部のみの入力 ${JSON.stringify(parts)} を報告する`, () => {
      assert.match(validate(parts).birthDate, /すべて入力/)
    })
  }

  for (const [birthYear, birthMonth, birthDay] of [
    ['2000', '2', '29'],
    ['2024', '02', '29'],
    ['1999', '12', '31'],
    ['0096', '2', '29'],
    ['2026', '10', '25'],
  ]) {
    it(`実在する日付 ${birthYear}-${birthMonth}-${birthDay} を許可する`, () => {
      assert.equal(
        validate({ birthYear, birthMonth, birthDay }).birthDate,
        undefined,
      )
    })
  }

  for (const [birthYear, birthMonth, birthDay] of [
    ['1900', '2', '29'],
    ['2025', '2', '29'],
    ['2000', '4', '31'],
    ['2000', '0', '1'],
    ['2000', '13', '1'],
    ['2000', '1', '0'],
    ['2000', '1', '32'],
    ['0000', '1', '1'],
  ]) {
    it(`実在しない日付 ${birthYear}-${birthMonth}-${birthDay} を拒否する`, () => {
      assert.match(
        validate({ birthYear, birthMonth, birthDay }).birthDate,
        /実在する日付/,
      )
    })
  }

  for (const [birthYear, birthMonth, birthDay] of [
    ['99', '1', '1'],
    ['2000', '1.5', '1'],
    ['2000', '1', '-1'],
    ['２０００', '１', '１'],
    ['2e03', '1', '1'],
    ['2000', '001', '1'],
  ]) {
    it(`数字の形式が不正な入力 ${birthYear}-${birthMonth}-${birthDay} を拒否する`, () => {
      assert.match(
        validate({ birthYear, birthMonth, birthDay }).birthDate,
        /半角数字/,
      )
    })
  }

  it('未来の生年月日を拒否する', () => {
    assert.match(
      validate({ birthYear: '2026', birthMonth: '10', birthDay: '26' })
        .birthDate,
      /今日以前/,
    )
  })
})
