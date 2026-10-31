import { useEffect, useState } from 'react'
import { Link } from '@tanstack/react-router'

const navigation = [
  { label: 'マイページ', href: '/' },
  { label: 'ログアウト', href: '/logout' },
]

const menuItems = [
  { label: 'プロフィールの変更', href: '/me' },
  { label: '連携アプリケーションの管理', href: '/me/consents' },
]

function LanguageSelector() {
  const [open, setOpen] = useState(false)

  return (
    <div className="relative">
      <button
        type="button"
        aria-expanded={open}
        aria-controls="language-menu"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-3 py-3
                   hover:bg-gray-100"
      >
        <span aria-hidden="true">◎</span>
        <span>Language</span>
        <span aria-hidden="true">⌄</span>
      </button>

      {open && (
        <div
          id="language-menu"
          className="absolute right-0 z-50 min-w-36
                     border bg-white shadow-lg"
        >
          <Link
            to="/"
            lang="ja"
            aria-current="page"
            className="block px-4 py-3 hover:bg-gray-100"
          >
            ✓ 日本語
          </Link>
          <Link to="/" lang="en" className="block px-4 py-3 hover:bg-gray-100">
            English
          </Link>
        </div>
      )}
    </div>
  )
}

function HeaderLogo() {
  const [logoUrl, setLogoUrl] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    let objectUrl: string | undefined

    async function loadLogo() {
      try {
        const response = await fetch('/.well-known/header', {
          signal: controller.signal,
        })
        if (!response.ok) return
        const blob = await response.blob()
        if (controller.signal.aborted) return
        objectUrl = URL.createObjectURL(blob)
        setLogoUrl(objectUrl)
      } catch {
        // Keep the text link when the logo is unavailable.
      }
    }

    void loadLogo()
    return () => {
      controller.abort()
      if (objectUrl) URL.revokeObjectURL(objectUrl)
    }
  }, [])

  return logoUrl ? (
    <img
      src={logoUrl}
      alt=""
      className="h-10 w-auto"
      onError={() => setLogoUrl(null)}
    />
  ) : (
    <span>ホーム</span>
  )
}

export default function HeaderComponent() {
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <header className="relative z-40 border-b bg-white text-solid-gray-900">
      <div
        className="flex h-20
                      items-center justify-between px-5"
      >
        {/* ロゴ */}
        <Link to="/" aria-label="ホーム">
          <HeaderLogo />
        </Link>

        {/* グローバルナビゲーション */}
        <nav
          aria-label="グローバルナビゲーション"
          className="flex items-center gap-2"
        >
          <div className="hidden items-center lg:flex">
            {navigation.map((item, index) => (
              <div key={item.label} className="flex items-center">
                {index === 3 && (
                  <span
                    aria-hidden="true"
                    className="mx-3 h-5 border-l border-gray-400"
                  />
                )}
                <Link
                  to={item.href}
                  className="px-3 py-3
                             hover:text-blue-800 hover:underline"
                >
                  {item.label}
                </Link>
              </div>
            ))}
          </div>

          {/* <Link to="/" className="hidden px-3 py-3 hover:underline lg:block">
            検索
          </Link> */}

          {/* すべてのメニュー */}
          <button
            type="button"
            aria-expanded={menuOpen}
            aria-controls="site-menu"
            onClick={() => setMenuOpen(!menuOpen)}
            className="flex items-center gap-2 px-3 py-3 hover:bg-gray-100"
          >
            <span aria-hidden="true">{menuOpen ? '✕' : '☰'}</span>
            <span>{menuOpen ? 'メニューを閉じる' : 'すべてのメニュー'}</span>
          </button>
        </nav>
      </div>

      {/* 展開メニュー */}
      {menuOpen && (
        <div
          id="site-menu"
          className="absolute left-0 right-0 top-full
                     border-t bg-white shadow-xl"
        >
          <nav aria-label="すべてのメニュー" className="px-6 py-8">
            <div className="mb-6 grid gap-3 lg:hidden">
              <Link to="/" onClick={() => setMenuOpen(false)}>
                検索
              </Link>
              {navigation.map((item) => (
                <Link
                  key={item.label}
                  to={item.href}
                  onClick={() => setMenuOpen(false)}
                >
                  {item.label}
                </Link>
              ))}
              <LanguageSelector />
            </div>

            <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {menuItems.map((item) => (
                <li key={item.label}>
                  <Link
                    to={item.href}
                    onClick={() => setMenuOpen(false)}
                    className="block border-b py-3
                               hover:text-blue-800 hover:underline"
                  >
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        </div>
      )}
    </header>
  )
}
