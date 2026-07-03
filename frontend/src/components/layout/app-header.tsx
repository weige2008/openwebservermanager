import { Link, useNavigate, useRouterState } from '@tanstack/react-router'
import { Dialog as BaseDialog } from '@base-ui/react/dialog'
import { KeyRound, LogOut, Menu, Moon, Plus, RefreshCw, Sun, UserCircle, X } from 'lucide-react'
import { useState } from 'react'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'

import { Button } from '../ui/button'
import { buttonVariants } from '../ui/button'
import { Badge } from '../ui/badge'
import { consoleNavItems } from './app-sidebar'
import { SystemBrand } from './system-brand'

const pageTitles: Record<string, string> = {
  '/app': '总览',
  '/app/servers': '服务器',
  '/app/credentials': '凭据',
  '/app/sessions': '连接会话',
  '/app/audit': '审计日志',
}

export function AppHeader({ sidebarOpen, onToggleSidebar }: { sidebarOpen: boolean; onToggleSidebar: () => void }) {
  const app = useApp()
  const navigate = useNavigate()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const title = pageTitles[pathname] || '控制台'
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
        <Button size='icon' variant='ghost' title={sidebarOpen ? '收起侧栏' : '展开侧栏'} onClick={handleSidebarButton}>
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
            <Link to='/app/servers' className={buttonVariants({ variant: 'ghost', size: 'sm' })}>服务器</Link>
            <Link to='/app/sessions' className={buttonVariants({ variant: 'ghost', size: 'sm' })}>会话</Link>
          </div>
          <Button className='hidden sm:inline-flex' size='sm' variant='outline' onClick={() => void app.refresh()}>
            <RefreshCw className='size-4' />
            <span>刷新</span>
          </Button>
          <Button className='hidden sm:inline-flex' size='sm' variant='outline' onClick={() => app.setModal({ type: 'credential' })}>
            <KeyRound className='size-4' />
            <span>凭据</span>
          </Button>
          <Button className='hidden sm:inline-flex' size='sm' variant='primary' onClick={() => app.setModal({ type: 'server' })}>
            <Plus className='size-4' />
            <span>服务器</span>
          </Button>
          <Button size='icon-sm' variant='outline' title='切换主题' onClick={() => app.setTheme(app.theme === 'dark' ? 'light' : 'dark')}>
            {app.theme === 'dark' ? <Sun className='size-4' /> : <Moon className='size-4' />}
          </Button>
          <Button className='hidden sm:inline-flex' size='sm' variant='outline' onClick={() => void logout()}>
            <UserCircle className='size-4' />
            <span>{app.auth?.username || 'admin'}</span>
            <LogOut className='size-4' />
          </Button>
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
            <BaseDialog.Close render={<Button size='icon-sm' variant='ghost' aria-label='关闭菜单'><X className='size-4' /></Button>} />
          </div>
          <div className='flex-1 overflow-auto py-3'>
            <div className='px-3 pb-2 text-xs font-medium text-muted-foreground'>应用</div>
            <nav className='grid gap-1 px-2'>
              {consoleNavItems.map((item) => {
                const Icon = item.icon
                const active = item.to === '/app' ? pathname === '/app' : pathname.startsWith(item.to)
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
                    {item.label}
                  </Link>
                )
              })}
            </nav>
            <div className='mt-4 grid gap-2 px-3'>
              <Button variant='outline' className='justify-start' onClick={() => void app.refresh().then(close)}>
                <RefreshCw className='size-4' />
                刷新数据
              </Button>
              <Button variant='outline' className='justify-start' onClick={() => { app.setModal({ type: 'credential' }); close() }}>
                <KeyRound className='size-4' />
                新增凭据
              </Button>
              <Button variant='primary' className='justify-start' onClick={() => { app.setModal({ type: 'server' }); close() }}>
                <Plus className='size-4' />
                新增服务器
              </Button>
            </div>
          </div>
          <div className='m-3 grid gap-3 rounded-lg border border-sidebar-border bg-card/70 p-3 text-xs'>
            <div className='flex items-center justify-between gap-2'>
              <span className='text-muted-foreground'>Gateway</span>
              <Badge tone={app.data.guacd?.address ? 'success' : 'warning'}>{app.data.guacd?.address ? 'ready' : 'offline'}</Badge>
            </div>
            <div className='truncate text-muted-foreground'>{app.data.guacd?.address || 'guacd 未连接'}</div>
            <div className='flex items-center gap-2'>
              <Button size='icon-sm' variant='outline' title='切换主题' onClick={() => app.setTheme(app.theme === 'dark' ? 'light' : 'dark')}>
                {app.theme === 'dark' ? <Sun className='size-4' /> : <Moon className='size-4' />}
              </Button>
              <Button variant='outline' className='min-w-0 flex-1 justify-start' onClick={() => void onLogout()}>
                <UserCircle className='size-4' />
                <span className='truncate'>{app.auth?.username || 'admin'}</span>
                <LogOut className='size-4 ms-auto' />
              </Button>
            </div>
          </div>
        </BaseDialog.Popup>
      </BaseDialog.Portal>
    </BaseDialog.Root>
  )
}
