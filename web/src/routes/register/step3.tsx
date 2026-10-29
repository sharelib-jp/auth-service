import { createFileRoute } from '@tanstack/react-router'
import { Heading, HeadingTitle } from '#/atoms/Heading'
import { Button } from '#/atoms/Button'
import { RegisterNavigation } from './-RegisterNavigation'

export const Route = createFileRoute('/register/step3')({
  validateSearch: (
    search: Record<string, unknown>,
  ): { status?: 'success' | 'error' } => ({
    status:
      search.status === 'success' || search.status === 'error'
        ? search.status
        : undefined,
  }),
  component: RouteComponent,
})

function RouteComponent() {
  return (
    <div>
      <Heading hasChip={false} size="36" className="mb-8">
        <HeadingTitle level="h3">アカウント作成の完了</HeadingTitle>
      </Heading>
      <div className="my-8 max-w-full">
        <RegisterNavigation currentStep={3} />
      </div>
      <p className="mb-8">登録が完了しました。</p>
      <Button
        aria-disabled={false}
        onClick={() => {}}
        size="lg"
        variant="outline"
        className="w-full"
      >
        ログイン画面へ戻る
      </Button>
    </div>
  )
}
