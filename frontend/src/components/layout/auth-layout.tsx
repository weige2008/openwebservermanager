import { Link } from '@tanstack/react-router'
import type { ReactNode } from 'react'

import { SystemBrand } from './system-brand'

export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className='relative grid min-h-svh bg-background text-foreground'>
      <Link to='/' className='absolute top-5 left-5 z-10 transition-opacity hover:opacity-80 sm:top-8 sm:left-8'>
        <SystemBrand />
      </Link>
      <div className='container mx-auto flex min-h-svh items-center px-4 pt-20 sm:pt-0'>
        <div className='mx-auto flex w-full flex-col justify-center space-y-6 sm:w-[480px] sm:p-8'>
          {children}
        </div>
      </div>
    </div>
  )
}
