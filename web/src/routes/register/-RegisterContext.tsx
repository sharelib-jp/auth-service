import { createContext, useContext, useState } from 'react'
import type { Dispatch, ReactNode, SetStateAction } from 'react'
import type { RegistrationValues } from './-validation'

type RegistrationContextValue = {
  values: RegistrationValues
  setValues: Dispatch<SetStateAction<RegistrationValues>>
}

const RegistrationContext = createContext<RegistrationContextValue | null>(null)

export function RegistrationProvider({ children }: { children: ReactNode }) {
  const [values, setValues] = useState<RegistrationValues>({
    screenName: '',
    accountName: '',
    email: '',
    birthYear: '',
    birthMonth: '',
    birthDay: '',
    gender: '',
  })

  return (
    <RegistrationContext value={{ values, setValues }}>
      {children}
    </RegistrationContext>
  )
}

export function useRegistration() {
  const context = useContext(RegistrationContext)

  if (context === null) {
    throw new Error('RegistrationProvider の内側で使用されていない')
  }

  return context
}
