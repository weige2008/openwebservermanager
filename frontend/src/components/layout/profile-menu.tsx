import { Menu as BaseMenu } from '@base-ui/react/menu'
import { useNavigate } from '@tanstack/react-router'
import { LogOut, RefreshCw, Settings } from 'lucide-react'
import type { ReactNode } from 'react'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'

export function ProfileMenu({ onLogout }: { onLogout: () => Promise<void> }) {
  const app = useApp()
  const navigate = useNavigate()
  const username = app.auth?.username || 'admin'
  const initials = username.slice(0, 2).toUpperCase()

  return (
    <BaseMenu.Root modal={false}>
      <BaseMenu.Trigger
        className='inline-flex size-6 items-center justify-center rounded-full p-0 text-sm font-medium outline-none transition-colors hover:bg-muted focus-visible:ring-3 focus-visible:ring-ring/50'
        aria-label={app.t('userMenu')}
      >
        <span className='grid size-6 place-items-center rounded-full bg-primary text-[11px] font-semibold text-primary-foreground'>{initials}</span>
      </BaseMenu.Trigger>
      <BaseMenu.Portal>
        <BaseMenu.Positioner sideOffset={8} align='end' className='z-[240]'>
          <BaseMenu.Popup className='z-[240] grid w-56 gap-1 rounded-xl bg-popover p-1 text-sm text-popover-foreground shadow-md ring-1 ring-foreground/10 outline-none'>
            <div className='flex items-center gap-2 px-1.5 py-1.5'>
              <span className='grid size-8 shrink-0 place-items-center rounded-full bg-primary text-xs font-semibold text-primary-foreground'>{initials}</span>
              <div className='min-w-0'>
                <p className='truncate font-medium'>{username}</p>
                <p className='truncate text-xs text-muted-foreground'>{app.auth?.role || 'admin'}</p>
              </div>
            </div>
            <BaseMenu.Separator className='-mx-1 my-1 h-px bg-border' />
            <MenuItem onClick={() => void app.refresh()}>
              <RefreshCw className='size-4' />
              {app.t('refreshData')}
            </MenuItem>
            <MenuItem onClick={() => void navigate({ to: '/app/settings' })}>
              <Settings className='size-4' />
              {app.t('settings')}
            </MenuItem>
            <BaseMenu.Separator className='-mx-1 my-1 h-px bg-border' />
            <MenuItem destructive onClick={() => void onLogout()}>
              <LogOut className='size-4' />
              {app.t('logout')}
            </MenuItem>
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>
  )
}

function MenuItem({
  children,
  destructive,
  disabled,
  onClick,
}: {
  children: ReactNode
  destructive?: boolean
  disabled?: boolean
  onClick?: () => void
}) {
  return (
    <BaseMenu.Item
      disabled={disabled}
      onClick={onClick}
      className={cn(
        'flex h-8 cursor-default items-center gap-2 rounded-lg px-2 text-sm outline-none transition-colors data-[highlighted]:bg-muted data-[disabled]:pointer-events-none data-[disabled]:opacity-50',
        destructive && 'text-destructive data-[highlighted]:bg-destructive/10'
      )}
    >
      {children}
    </BaseMenu.Item>
  )
}
