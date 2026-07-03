import { Link, useRouterState } from '@tanstack/react-router'
import { FileClock, Home, KeyRound, MonitorUp, Server, Settings } from 'lucide-react'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'

import { Badge } from '../ui/badge'
import { SystemBrand } from './system-brand'

export const consoleNavItems = [
  { to: '/app', label: '总览', icon: Home },
  { to: '/app/servers', label: '服务器', icon: Server },
  { to: '/app/credentials', label: '凭据', icon: KeyRound },
  { to: '/app/sessions', label: '会话', icon: MonitorUp },
  { to: '/app/audit', label: '审计', icon: FileClock },
] as const

export function AppSidebar() {
  const { data } = useApp()
  const pathname = useRouterState({ select: (state) => state.location.pathname })

  return (
    <aside className='hidden w-64 shrink-0 border-r border-sidebar-border bg-sidebar text-sidebar-foreground md:flex md:flex-col'>
      <div className='flex h-[var(--app-header-height)] items-center border-b border-sidebar-border px-4'>
        <SystemBrand clickable />
      </div>
      <div className='flex-1 overflow-auto py-2'>
        <div className='px-2 pb-2'>
          <div className='px-2 py-2 text-xs font-medium text-muted-foreground'>应用</div>
          <nav className='grid gap-1'>
            {consoleNavItems.map((item) => {
              const Icon = item.icon
              const active = item.to === '/app' ? pathname === '/app' : pathname.startsWith(item.to)
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  className={cn(
                    'flex h-9 items-center gap-2 rounded-md px-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                    active && 'bg-sidebar-accent text-sidebar-accent-foreground shadow-sm'
                  )}
                >
                  <span className='grid size-7 place-items-center rounded-md bg-background/70'>
                    <Icon className='size-4' />
                  </span>
                  {item.label}
                </Link>
              )
            })}
          </nav>
        </div>
      </div>
      <div className='m-3 grid gap-2 rounded-lg border border-sidebar-border bg-card/70 p-3 text-xs'>
        <div className='flex items-center justify-between gap-2'>
          <span className='text-muted-foreground'>Gateway</span>
          <Badge tone={data.guacd?.address ? 'success' : 'warning'}>{data.guacd?.address ? 'ready' : 'offline'}</Badge>
        </div>
        <div className='flex items-center gap-2 text-muted-foreground'>
          <Settings className='size-3.5' />
          <span className='truncate'>{data.guacd?.address || 'guacd 未连接'}</span>
        </div>
      </div>
    </aside>
  )
}
