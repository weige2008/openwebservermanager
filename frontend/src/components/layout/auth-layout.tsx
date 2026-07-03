import { Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'

import { SystemBrand } from './system-brand'
import { LanguageSwitcher } from './language-switcher'
import { ThemeSwitch } from './theme-switch'

export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className='relative grid h-svh max-w-none bg-background text-foreground'>
      <Link to='/' className='absolute top-4 left-4 z-10 transition-opacity hover:opacity-80 sm:top-8 sm:left-8'>
        <SystemBrand variant='auth' />
      </Link>
      <div className='absolute top-4 right-4 z-10 flex items-center gap-1 sm:top-8 sm:right-8'>
        <LanguageSwitcher className='size-9' />
        <ThemeSwitch className='size-9' />
      </div>
      <div className='container mx-auto flex items-center px-4 pt-16 sm:pt-0'>
        <div className='mx-auto flex w-full flex-col justify-center space-y-2 py-8 sm:w-[480px] sm:p-8'>
          {children}
        </div>
      </div>
    </div>
  )
}
