import React from 'react'
import { Tab, TabList, TabItem, TabPanel, useTab } from '#/atoms/Tab'
import {
  ProgressIndicator,
  ProgressIndicatorSpinner,
} from '#/atoms/ProgressIndicator'
import { useNodeInfo } from '#/lib/useNodeInfo'
import { useMe } from '#/lib/useMe'

export const IdentificationComponent = () => {
  const { getListProps, getTabProps, getPanelProps } = useTab({
    defaultSelectedIndex: 0,
  })

  const [updatedAt, setUpdatedAt] = React.useState<Date | null>(null)

  const [
    loadedIdentificationBarcodeStatus,
    setLoadedIdentificationBarcodeStatus,
  ] = React.useState<'loading' | 'loaded' | 'error'>('loading')

  const [IdentificationBarcodeSrc, setIdentificationBarcodeSrc] =
    React.useState<string | null>(null)

  const {
    data: nodeInfo,
    isPending: nodeInfoPending,
    isError: nodeInfoError,
  } = useNodeInfo()

  const { data: me, isPending: mePending, isError: meError } = useMe()

  React.useEffect(() => {
    const controller = new AbortController()
    let url: string | undefined

    async function fetch1DIdentificationBarcode() {
      try {
        const response = await fetch('/api/users/me/barcode', {
          method: 'GET',
          credentials: 'same-origin',
          signal: controller.signal,
        })

        if (!response.ok) throw new Error('Failed to load barcode')

        const blob = await response.blob()
        if (controller.signal.aborted) return
        url = URL.createObjectURL(blob)
        setIdentificationBarcodeSrc(url)
        setLoadedIdentificationBarcodeStatus('loaded')
        setUpdatedAt(new Date())
      } catch {
        if (!controller.signal.aborted) {
          setLoadedIdentificationBarcodeStatus('error')
        }
      }
    }

    void fetch1DIdentificationBarcode()

    return () => {
      controller.abort()
      if (url) URL.revokeObjectURL(url)
    }
  }, [])

  return (
    <div>
      <Tab>
        <TabList {...getListProps()}>
          <TabItem {...getTabProps(0)}>バーコード</TabItem>
          <TabItem {...getTabProps(1)}>ワンタイム QR</TabItem>
        </TabList>
        <TabPanel {...getPanelProps(0)} className="">
          {loadedIdentificationBarcodeStatus == 'loading' ? (
            <ProgressIndicator type="inlined">
              <ProgressIndicatorSpinner size="sm" />
              <p>読み込み中</p>
            </ProgressIndicator>
          ) : null}
          {loadedIdentificationBarcodeStatus == 'loaded' ? (
            <>
              <div className="flex justify-center items-center">
                <img
                  src={IdentificationBarcodeSrc ?? undefined}
                  alt="バーコード"
                  className="max-h-36"
                />
              </div>
              <dl className="text-sm text-gray-500 truncate mx-1 my-2">
                <div className="flex gap-1">
                  <dt>ユーザ ID:</dt>
                  <dd>
                    {mePending ? '読み込み中' : null}
                    {meError ? '取得に失敗しました' : null}
                    {me ? me.ID : null}
                  </dd>
                </div>
                <div className="flex gap-1">
                  <dt>利用者記号:</dt>
                  <dd>
                    {mePending ? '読み込み中' : null}
                    {meError ? '取得に失敗しました' : null}
                    {me ? me.LibraryId : null}
                  </dd>
                </div>
                <div className="flex gap-1">
                  <dt>図書館:</dt>
                  <dd>
                    {nodeInfoPending ? '読み込み中' : null}
                    {nodeInfoError ? '取得に失敗しました' : null}
                    {nodeInfo
                      ? `${nodeInfo.metadata.nodeName} (${nodeInfo.metadata.nodeDomain})`
                      : null}
                  </dd>
                </div>
                <div className="flex gap-1">
                  <dt>取得日時:</dt>
                  <dd>
                    {updatedAt ? (
                      <time dateTime={updatedAt.toISOString()}>
                        {updatedAt.toLocaleString()}
                      </time>
                    ) : null}
                  </dd>
                </div>
              </dl>
            </>
          ) : null}
          {loadedIdentificationBarcodeStatus == 'error' ? (
            <p role="alert">バーコードの読み込みに失敗しました</p>
          ) : null}
        </TabPanel>
        <TabPanel {...getPanelProps(1)} className="">
          <p>ワンタイム QR コードは未実装です</p>
        </TabPanel>
      </Tab>
    </div>
  )
}
