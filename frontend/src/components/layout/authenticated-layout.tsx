import type { ReactNode } from 'react'

import { AppHeader } from './app-header'
import { AppSidebar } from './app-sidebar'

export function AuthenticatedLayout({ children }: { children: ReactNode }) {
  return (
    <div className='flex min-h-svh flex-col bg-background text-foreground'>
      <AppHeader />
      <div className='flex min-h-0 flex-1'>
        <AppSidebar />
        <main className='h-[calc(100svh-var(--app-header-height))] min-w-0 flex-1 overflow-auto'>
          <div className='@container/content grid content-start gap-4 p-4 md:p-5'>{children}</div>
        </main>
      </div>
    </div>
  )
}
