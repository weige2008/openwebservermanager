import { Link, useRouterState } from '@tanstack/react-router'
import { FileClock, Home, MonitorUp, Server, Settings } from 'lucide-react'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'

import { Badge } from '../ui/badge'

export const consoleNavItems = [
  { to: '/app', label: 'overview', icon: Home },
  { to: '/app/servers', label: 'assets', icon: Server },
  { to: '/app/sessions', label: 'sessions', icon: MonitorUp },
  { to: '/app/audit', label: 'audit', icon: FileClock },
] as const

export function AppSidebar({ collapsed = false }: { collapsed?: boolean }) {
  const { appearance, data, t } = useApp()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const framed = appearance.sidebarStyle !== 'default'

  return (
    <aside
      data-state={collapsed ? 'collapsed' : 'expanded'}
      className={cn(
        'hidden shrink-0 bg-sidebar text-sidebar-foreground transition-[width] duration-200 ease-linear md:flex md:flex-col',
        framed ? 'm-2 h-[calc(100svh-var(--app-header-height)-1rem)] rounded-xl border border-sidebar-border shadow-sm' : 'h-[calc(100svh-var(--app-header-height))] border-r border-sidebar-border',
        appearance.sidebarStyle === 'inset' && 'bg-sidebar/85',
        collapsed ? (framed ? 'w-12' : 'w-11') : framed ? 'w-56' : 'w-52'
      )}
    >
      <div className='flex-1 overflow-auto py-2'>
        <div className='px-2 pb-2'>
          <div className={cn('flex h-8 items-center rounded-md px-2 text-xs font-medium text-muted-foreground transition-opacity', collapsed && 'pointer-events-none opacity-0')}>
            {t('app')}
          </div>
          <nav className='grid gap-1'>
            {consoleNavItems.map((item) => {
              const Icon = item.icon
              const active = item.to === '/app' ? pathname === '/app' : pathname.startsWith(item.to)
              const label = t(item.label)
              return (
                <Link
                  key={item.to}
                  to={item.to}
                  title={label}
                  className={cn(
                    'group/menu-button flex h-8 min-w-0 items-center gap-2 overflow-hidden rounded-md p-2 text-sm font-medium text-muted-foreground outline-none transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:ring-2 focus-visible:ring-sidebar-ring',
                    active && 'bg-sidebar-accent text-sidebar-accent-foreground',
                    collapsed && 'size-8 justify-center'
                  )}
                >
                  <Icon className='size-4 shrink-0' />
                  <span className={cn('truncate', collapsed && 'sr-only')}>{label}</span>
                </Link>
              )
            })}
          </nav>
        </div>
      </div>
      <div className={cn('m-2 grid gap-2 rounded-lg bg-card/70 p-2 text-xs ring-1 ring-sidebar-border', collapsed && 'place-items-center p-1')}>
        <div className='flex items-center justify-between gap-2'>
          <span className={cn('text-muted-foreground', collapsed && 'sr-only')}>{t('gateway')}</span>
          <Badge tone={data.guacd?.address ? 'success' : 'warning'}>{data.guacd?.address ? t('gatewayReady') : t('gatewayOffline')}</Badge>
        </div>
        <div className={cn('flex items-center gap-2 text-muted-foreground', collapsed && 'sr-only')}>
          <Settings className='size-3.5' />
          <span className='truncate'>{data.guacd?.address || t('guacdOffline')}</span>
        </div>
      </div>
    </aside>
  )
}
