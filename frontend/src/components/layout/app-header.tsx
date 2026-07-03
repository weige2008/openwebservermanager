import { Dialog as BaseDialog } from '@base-ui/react/dialog'
import { Link, useNavigate, useRouterState } from '@tanstack/react-router'
import { KeyRound, LogOut, Menu, Plus, RefreshCw, UserCircle, X } from 'lucide-react'
import { useState } from 'react'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'

import { Badge } from '../ui/badge'
import { Button } from '../ui/button'
import { buttonVariants } from '../ui/button'
import { AppearanceDrawer } from './appearance-drawer'
import { CommandSearch } from './command-search'
import { consoleNavItems } from './app-sidebar'
import { LanguageSwitcher } from './language-switcher'
import { NotificationButton } from './notification-button'
import { ProfileMenu } from './profile-menu'
import { SystemBrand } from './system-brand'

const pageTitleKeys: Record<string, string> = {
  '/app': 'overview',
  '/app/servers': 'servers',
  '/app/credentials': 'servers',
  '/app/sessions': 'sessions',
  '/app/audit': 'audit',
}

export function AppHeader({ sidebarOpen, onToggleSidebar }: { sidebarOpen: boolean; onToggleSidebar: () => void }) {
  const app = useApp()
  const navigate = useNavigate()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const title = pathname === '/app/servers' || pathname === '/app/credentials'
    ? `${app.t('servers')} / ${app.t('credentials')}`
    : app.t(pageTitleKeys[pathname] || 'dashboard')
  const [mobileOpen, setMobileOpen] = useState(false)

  const handleSidebarButton = () => {
    if (window.matchMedia('(min-width: 768px)').matches) {
      onToggleSidebar()
      return
    }
    setMobileOpen(true)
  }

  const logout = async () => {
    await app.logout()
    await navigate({ to: '/' })
    setMobileOpen(false)
  }

  return (
    <>
      <header className='sticky top-0 z-40 h-[var(--app-header-height)] w-full shrink-0 bg-transparent'>
        <div className='flex h-full items-center gap-1.5 px-2 sm:gap-2 sm:px-3'>
          <Button size='icon' variant='ghost' title={sidebarOpen ? app.t('closeSidebar') : app.t('openSidebar')} onClick={handleSidebarButton}>
            <Menu className='size-4' />
          </Button>
          <div className='min-w-0'>
            <SystemBrand clickable />
          </div>
          <div className='hidden min-w-0 border-l border-border pl-3 md:block'>
            <div className='text-xs text-muted-foreground'>ServerManager / {title}</div>
          </div>
          <div className='ms-auto flex min-w-0 items-center gap-1 sm:gap-2'>
            <div className='hidden lg:flex'>
              <Link to='/app/servers' className={buttonVariants({ variant: 'ghost', size: 'sm' })}>
                {app.t('servers')} / {app.t('credentials')}
              </Link>
              <Link to='/app/sessions' className={buttonVariants({ variant: 'ghost', size: 'sm' })}>
                {app.t('sessions')}
              </Link>
            </div>
            <CommandSearch />
            <div className='hidden xl:flex items-center gap-2'>
              <Button size='sm' variant='outline' onClick={() => void app.refresh()}>
                <RefreshCw className='size-4' />
                <span>{app.t('refresh')}</span>
              </Button>
              <Button size='sm' variant='outline' onClick={() => app.setModal({ type: 'credential' })}>
                <KeyRound className='size-4' />
                <span>{app.t('credentials')}</span>
              </Button>
              <Button size='sm' variant='primary' onClick={() => app.setModal({ type: 'server' })}>
                <Plus className='size-4' />
                <span>{app.t('servers')}</span>
              </Button>
            </div>
            <NotificationButton size='icon-sm' className='rounded-md' />
            <LanguageSwitcher size='icon-sm' className='rounded-md' />
            <AppearanceDrawer className='size-7 rounded-md' />
            <ProfileMenu onLogout={logout} />
          </div>
        </div>
      </header>
      <MobileNavDrawer open={mobileOpen} onOpenChange={setMobileOpen} onLogout={logout} />
    </>
  )
}

function MobileNavDrawer({
  open,
  onOpenChange,
  onLogout,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onLogout: () => Promise<void>
}) {
  const app = useApp()
  const pathname = useRouterState({ select: (state) => state.location.pathname })

  const close = () => onOpenChange(false)

  return (
    <BaseDialog.Root open={open} onOpenChange={onOpenChange}>
      <BaseDialog.Portal>
        <BaseDialog.Backdrop className='fixed inset-0 z-50 bg-black/45 md:hidden' />
        <BaseDialog.Popup className='fixed inset-y-0 left-0 z-50 flex w-[min(17rem,calc(100vw-2rem))] flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground shadow-2xl outline-none md:hidden'>
          <div className='flex h-[var(--app-header-height)] items-center justify-between border-b border-sidebar-border px-4'>
            <SystemBrand clickable />
            <BaseDialog.Close render={<Button size='icon-sm' variant='ghost' aria-label={app.t('closeMenu')} />}>
              <X className='size-4' />
            </BaseDialog.Close>
          </div>
          <div className='flex-1 overflow-auto py-3'>
            <div className='px-3 pb-2 text-xs font-medium text-muted-foreground'>{app.t('app')}</div>
            <nav className='grid gap-1 px-2'>
              {consoleNavItems.map((item) => {
                const Icon = item.icon
                const active = item.to === '/app' ? pathname === '/app' : pathname.startsWith(item.to)
                const label = item.to === '/app/servers' ? `${app.t('servers')} / ${app.t('credentials')}` : app.t(item.label)
                return (
                  <Link
                    key={item.to}
                    to={item.to}
                    onClick={close}
                    className={cn(
                      'flex h-10 items-center gap-2 rounded-md px-2 text-sm font-medium text-muted-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                      active && 'bg-sidebar-accent text-sidebar-accent-foreground shadow-sm'
                    )}
                  >
                    <span className='grid size-7 place-items-center rounded-md bg-background/70'>
                      <Icon className='size-4' />
                    </span>
                    {label}
                  </Link>
                )
              })}
            </nav>
            <div className='mt-4 grid gap-2 px-3'>
              <Button variant='outline' className='justify-start' onClick={() => void app.refresh().then(close)}>
                <RefreshCw className='size-4' />
                {app.t('refreshData')}
              </Button>
              <Button
                variant='outline'
                className='justify-start'
                onClick={() => {
                  app.setModal({ type: 'credential' })
                  close()
                }}
              >
                <KeyRound className='size-4' />
                {app.t('addCredential')}
              </Button>
              <Button
                variant='primary'
                className='justify-start'
                onClick={() => {
                  app.setModal({ type: 'server' })
                  close()
                }}
              >
                <Plus className='size-4' />
                {app.t('addServer')}
              </Button>
            </div>
          </div>
          <div className='m-3 grid gap-3 rounded-lg border border-sidebar-border bg-card/70 p-3 text-xs'>
            <div className='flex items-center justify-between gap-2'>
              <span className='text-muted-foreground'>{app.t('gateway')}</span>
              <Badge tone={app.data.guacd?.address ? 'success' : 'warning'}>{app.data.guacd?.address ? app.t('gatewayReady') : app.t('gatewayOffline')}</Badge>
            </div>
            <div className='truncate text-muted-foreground'>{app.data.guacd?.address || app.t('guacdOffline')}</div>
            <div className='grid grid-cols-4 gap-2'>
              <NotificationButton size='icon-sm' variant='outline' />
              <LanguageSwitcher size='icon-sm' variant='outline' />
              <AppearanceDrawer className='size-7 rounded-md border border-border bg-background' />
              <Button variant='outline' className='min-w-0 justify-start col-span-1 px-2' onClick={() => void onLogout()} title={app.t('logout')}>
                <LogOut className='size-4' />
              </Button>
            </div>
            <div className='flex items-center gap-2 rounded-lg border border-border bg-background px-2 py-1.5'>
              <UserCircle className='size-4 text-muted-foreground' />
              <span className='truncate'>{app.auth?.username || 'admin'}</span>
            </div>
          </div>
        </BaseDialog.Popup>
      </BaseDialog.Portal>
    </BaseDialog.Root>
  )
}
