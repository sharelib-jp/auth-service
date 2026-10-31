export async function logout(): Promise<void> {
  const response = await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'same-origin',
  })

  // An expired or missing session is already logged out.
  if (!response.ok && response.status !== 401) {
    throw new Error('ログアウトに失敗しました。')
  }
}
