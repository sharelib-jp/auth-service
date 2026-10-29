import { queryOptions, useQuery } from '@tanstack/react-query'

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

export const meQueryOptions = queryOptions({
  queryKey: ['me'],
  queryFn: ({ signal }) => fetchMe(signal),
  retry: false,
})

export function useMe() {
  return useQuery(meQueryOptions)
}
