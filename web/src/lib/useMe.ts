import {
  queryOptions,
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'

export type Me = {
  ID: string
  LibraryId: number
  LibraryIdFormatted: string
  Barcode: string
  UserName: string
  Name: string
  Email: string
  CreatedAt: string
  UpdatedAt: string
}

export async function fetchMe(signal?: AbortSignal): Promise<Me> {
  const response = await fetch('/api/users/me', {
    credentials: 'same-origin',
    signal,
  })

  if (!response.ok) {
    throw new Error(`ユーザー情報の取得に失敗しました (${response.status})`)
  }

  return (await response.json()) as Me
}

function usePatchMe(
  field: 'UserName' | 'Name' | 'Email',
  path: string,
  label: string,
) {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (value: string) => {
      const response = await fetch(`/api/users/me/${path}`, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [field]: value }),
      })
      if (!response.ok) {
        throw new Error(`${label}の更新に失敗しました (${response.status})`)
      }
    },
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['me'] }),
  })
}

export function usePatchMeUserName() {
  return usePatchMe('UserName', 'username', 'ユーザー名')
}

export function usePatchMeName() {
  return usePatchMe('Name', 'name', '表示名')
}

export function usePatchMeEmail() {
  return usePatchMe('Email', 'email', 'メールアドレス')
}

export const meQueryOptions = queryOptions({
  queryKey: ['me'],
  queryFn: ({ signal }) => fetchMe(signal),
  retry: false,
})

export function useMe() {
  return useQuery(meQueryOptions)
}
