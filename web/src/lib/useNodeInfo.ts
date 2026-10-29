import { queryOptions, useQuery } from '@tanstack/react-query'

export type NodeInfoContact = {
  name: string
  email: string
}

export type NodeInfo = {
  version: string
  metadata: {
    nodeName: string
    nodeDomain: string
    nodeAdmins: Array<NodeInfoContact>
    maintainer: Array<NodeInfoContact>
  }
}

export async function FetchNodeInfo(signal?: AbortSignal): Promise<NodeInfo> {
  const response = await fetch('/api/.well-known/nodeinfo', {
    signal,
  })

  if (!response.ok) {
    throw new Error(`NodeInfo の取得に失敗しました (${response.status})`)
  }

  return (await response.json()) as NodeInfo
}

export const nodeInfoQueryOptions = queryOptions({
  queryKey: ['nodeInfo'],
  queryFn: ({ signal }) => FetchNodeInfo(signal),
  staleTime: 5 * 60 * 1000,
})

export function useNodeInfo() {
  return useQuery(nodeInfoQueryOptions)
}
