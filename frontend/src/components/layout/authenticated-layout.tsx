import type { ReactNode } from 'react'
import { useEffect, useState } from 'react'

import { AppHeader } from './app-header'
import { AppSidebar } from './app-sidebar'

export function AuthenticatedLayout({ children }: { children: ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(() => localStorage.getItem('servermanager:sidebar') !== 'collapsed')

  useEffect(() => {
    localStorage.setItem('servermanager:sidebar', sidebarOpen ? 'expanded' : 'collapsed')
  }, [sidebarOpen])

  return (
    <div className='flex min-h-svh w-full flex-col bg-background text-foreground'>
      <AppHeader sidebarOpen={sidebarOpen} onToggleSidebar={() => setSidebarOpen((open) => !open)} />
      <div className='flex min-h-0 w-full flex-1'>
        <AppSidebar collapsed={!sidebarOpen} />
        <main className='@container/content h-[calc(100svh-var(--app-header-height))] min-h-0 min-w-0 flex-1 overflow-auto p-3 sm:p-4 md:p-5'>
          <div className='app-content-shell grid min-h-full content-start gap-4'>{children}</div>
        </main>
      </div>
    </div>
  )
}
