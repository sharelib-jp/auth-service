import { Outlet, createFileRoute } from '@tanstack/react-router'
import { RegistrationProvider } from './-RegisterContext'

export const Route = createFileRoute('/register')({
  component: RegistrationLayout,
})

function RegistrationLayout() {
  return (
    <RegistrationProvider>
      <Outlet />
    </RegistrationProvider>
  )
}
