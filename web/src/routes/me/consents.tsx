import { createFileRoute } from '@tanstack/react-router'
import { Heading, HeadingTitle } from '#/atoms/Heading'
import { OAuthApplicationConsents } from '#/components/OAuthApplicationConsents'

export const Route = createFileRoute('/me/consents')({
  component: RouteComponent,
})

function RouteComponent() {
  return (
    <>
      <Heading hasChip={false} size="24" className="mb-8">
        <HeadingTitle level="h2">アプリケーションへのアクセス許可</HeadingTitle>
      </Heading>
      <OAuthApplicationConsents />
    </>
  )
}
