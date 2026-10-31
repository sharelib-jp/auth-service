import { useEffect, useRef, useState } from 'react'
import type { PointerEvent } from 'react'

export type ToastVariant = 'success' | 'error' | 'info'

export type ToastProps = {
  message: string
  variant?: ToastVariant
  duration?: number
  onClose: () => void
}

const variantStyles: Record<ToastVariant, string> = {
  success: 'bg-green-800 text-white',
  error: 'bg-red-800 text-white',
  info: 'bg-gray-700 text-white',
}

/** A toast is displayed while mounted; its owner removes it in onClose. */
export function Toast({
  message,
  variant = 'info',
  duration = 6000,
  onClose,
}: ToastProps) {
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose
  const start = useRef<{ x: number; y: number } | null>(null)
  const [offset, setOffset] = useState({ x: 0, y: 0 })

  useEffect(() => {
    const timer = window.setTimeout(() => onCloseRef.current(), duration)
    return () => window.clearTimeout(timer)
  }, [duration])

  function handlePointerMove(event: PointerEvent<HTMLDivElement>) {
    if (!start.current) return
    setOffset({
      x: Math.max(0, event.clientX - start.current.x),
      y: Math.max(0, event.clientY - start.current.y),
    })
  }

  function handlePointerEnd(event: PointerEvent<HTMLDivElement>) {
    if (!start.current) return
    const distanceX = event.clientX - start.current.x
    const distanceY = event.clientY - start.current.y
    start.current = null
    setOffset({ x: 0, y: 0 })
    if (event.type !== 'pointercancel' && (distanceX > 80 || distanceY > 80)) {
      onCloseRef.current()
    }
  }

  return (
    <div
      className={`fixed right-4 bottom-4 z-50 flex w-[min(24rem,calc(100vw-2rem))] touch-none items-start gap-4 rounded-lg p-4 shadow-lg ${variantStyles[variant]}`}
      style={{ transform: `translate(${offset.x}px, ${offset.y}px)` }}
      onPointerDown={(event) => {
        if (
          event.button !== 0 ||
          (event.target as HTMLElement).closest('button')
        )
          return
        start.current = { x: event.clientX, y: event.clientY }
        event.currentTarget.setPointerCapture(event.pointerId)
      }}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerEnd}
      onPointerCancel={handlePointerEnd}
    >
      <p
        className="min-w-0 flex-1 break-words text-sm"
        role={variant === 'error' ? 'alert' : 'status'}
      >
        {message}
      </p>
      <button
        type="button"
        aria-label="通知を閉じる"
        className="flex h-4 w-4 shrink-0 items-center justify-center rounded focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
        onClick={onClose}
      >
        <span aria-hidden="true" className="text-xl leading-none">
          ×
        </span>
      </button>
    </div>
  )
}
