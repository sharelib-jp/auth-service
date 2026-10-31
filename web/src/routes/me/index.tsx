import { createFileRoute } from '@tanstack/react-router'
import { EditProfileComponent } from '#/components/EditProfile'
import { Heading, HeadingTitle } from '#/atoms/Heading'

export const Route = createFileRoute('/me/')({
  component: RouteComponent,
})

function RouteComponent() {
  return (
    <>
      <Heading hasChip={false} size="24" className="mb-8">
        <HeadingTitle level="h2">プロフィールの変更</HeadingTitle>
      </Heading>
      <EditProfileComponent />
    </>
  )
}
