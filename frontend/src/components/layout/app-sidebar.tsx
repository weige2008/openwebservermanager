import { Link, useRouterState } from '@tanstack/react-router'
import { Home, LayoutDashboard, MonitorUp, Settings } from 'lucide-react'
import { AnimatePresence, motion, useReducedMotion } from 'motion/react'

import { useApp } from '@/app/app-provider'
import {
  MOTION_TRANSITION,
  MOTION_VARIANTS,
  SIDEBAR_ITEM_VARIANTS,
  SIDEBAR_STAGGER_VARIANTS,
} from '@/lib/motion'
import { platformLabel, platformNavGroups } from '@/lib/platform'
import { cn } from '@/lib/utils'

import { Badge } from '../ui/badge'

export const consoleNavItems = [
  { to: '/app', label: 'overview', icon: Home },
  { to: '/access', label: 'accessPortal', icon: LayoutDashboard },
  { to: '/app/servers', label: 'connectionWorkspace', icon: MonitorUp },
] as const

export function AppSidebar({ collapsed = false }: { collapsed?: boolean }) {
  const { appearance, data, t, locale } = useApp()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const shouldReduce = useReducedMotion()
  const framed = appearance.sidebarStyle !== 'default'
  const activeSection = [...consoleNavItems.map((item) => item.to), ...platformNavGroups.flatMap((group) => group.items.map((item) => item.route))]
    .find((to) => (to === '/app' ? pathname === '/app' : pathname.startsWith(to))) ?? '/app'
  const animationKey = `${collapsed ? 'collapsed' : 'expanded'}:${activeSection}`

  const navigation = (
    <div className='flex flex-col'>
      <div className='px-2 pb-2'>
        <div className={cn('flex h-8 items-center rounded-md px-2 text-xs font-medium text-muted-foreground transition-opacity', collapsed && 'pointer-events-none opacity-0')}>
          {t('app')}
        </div>
        <motion.nav
          variants={shouldReduce ? undefined : SIDEBAR_STAGGER_VARIANTS}
          initial={shouldReduce ? undefined : 'initial'}
          animate={shouldReduce ? undefined : 'animate'}
          className='grid gap-1'
        >
          {consoleNavItems.map((item) => {
            const Icon = item.icon
            const active = item.to === '/app' ? pathname === '/app' : pathname.startsWith(item.to)
            const label = t(item.label)
            return (
              <motion.div key={item.to} variants={shouldReduce ? undefined : SIDEBAR_ITEM_VARIANTS}>
                <Link
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
              </motion.div>
            )
          })}
        </motion.nav>
      </div>
      {platformNavGroups.map((group) => {
        const GroupIcon = group.icon
        return (
          <div key={group.labelZh} className='px-2 pb-2'>
            <div className={cn('flex h-8 items-center gap-2 rounded-md px-2 text-xs font-medium text-muted-foreground transition-opacity', collapsed && 'pointer-events-none justify-center px-0')}>
              <GroupIcon className='size-3.5 shrink-0' />
              <span className={cn('truncate', collapsed && 'sr-only')}>{platformLabel(group, locale)}</span>
            </div>
            <motion.nav
              variants={shouldReduce ? undefined : SIDEBAR_STAGGER_VARIANTS}
              initial={shouldReduce ? undefined : 'initial'}
              animate={shouldReduce ? undefined : 'animate'}
              className='grid gap-1'
            >
              {group.items.map((item) => {
                const Icon = item.icon
                const active = pathname.startsWith(item.route)
                const label = platformLabel(item, locale)
                return (
                  <motion.div key={item.route} variants={shouldReduce ? undefined : SIDEBAR_ITEM_VARIANTS}>
                    <Link
                      to={item.route}
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
                  </motion.div>
                )
              })}
            </motion.nav>
          </div>
        )
      })}
    </div>
  )

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
        {shouldReduce ? (
          navigation
        ) : (
          <AnimatePresence mode='wait' initial={false}>
            <motion.div
              key={animationKey}
              initial={MOTION_VARIANTS.sidebarSlide.initial}
              animate={MOTION_VARIANTS.sidebarSlide.animate}
              exit={MOTION_VARIANTS.sidebarSlide.exit}
              transition={MOTION_TRANSITION.fast}
            >
              {navigation}
            </motion.div>
          </AnimatePresence>
        )}
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
