import { Menu as BaseMenu } from '@base-ui/react/menu'
import { Bell, RadioTower } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'
import { useNotificationStore } from '@/stores/notification-store'

import { Badge } from '../ui/badge'
import { buttonVariants, type ButtonProps } from '../ui/button'

export function NotificationButton({
  className,
  size = 'icon',
  variant = 'ghost',
}: {
  className?: string
  size?: ButtonProps['size']
  variant?: ButtonProps['variant']
}) {
  const { data } = useApp()
  const { t } = useTranslation()
  const productName = t('productName')
  const [activeTab, setActiveTab] = useState<'notice' | 'timeline'>('notice')
  const readKeys = useNotificationStore((state) => state.readKeys)
  const markRead = useNotificationStore((state) => state.markRead)

  const notifications = useMemo(() => {
    const gatewayReady = Boolean(data.guacd?.address)
    return [
      {
        id: `gateway:${gatewayReady ? 'online' : 'offline'}`,
        type: gatewayReady ? 'success' : 'warning',
        title: gatewayReady ? t('rdpGatewayOnline') : t('rdpGatewayOffline'),
        body: gatewayReady ? data.guacd?.address || '' : t('rdpGatewayOfflineBody'),
        time: t('today'),
      },
      {
        id: 'audit',
        type: 'info',
        title: t('sessionAuditEnabled'),
        body: t('sessionAuditEnabledBody'),
        time: t('today'),
      },
    ]
  }, [data.guacd?.address, t])

  const noticeKey = 'notice:connection-workspace'
  const notificationKeys = useMemo(() => [noticeKey, ...notifications.map((item) => `timeline:${item.id}`)], [notifications])
  const unreadCount = notificationKeys.filter((key) => !readKeys.includes(key)).length

  return (
    <BaseMenu.Root modal={false} onOpenChange={(open) => open && markRead(notificationKeys)}>
      <BaseMenu.Trigger className={cn(buttonVariants({ variant, size }), 'relative p-0', className)} aria-label={t('notifications')} title={t('notifications')}>
        <Bell className='size-[1.05rem]' />
        {unreadCount > 0 ? (
          <Badge tone='danger' className='absolute -top-1 -right-1 flex h-4 min-w-4 items-center justify-center px-1 text-[10px]'>
            {unreadCount}
          </Badge>
        ) : null}
        <span className='sr-only'>{t('notifications')}</span>
      </BaseMenu.Trigger>
      <BaseMenu.Portal>
        <BaseMenu.Positioner sideOffset={8} align='end' className='z-[240]'>
          <BaseMenu.Popup className='z-[240] grid w-[min(26rem,calc(100vw-1rem))] gap-3 rounded-xl bg-popover p-3 text-sm text-popover-foreground shadow-md ring-1 ring-foreground/10 outline-none'>
            <div className='px-1'>
              <div className='font-medium'>{t('systemAnnouncements')}</div>
              <p className='mt-1 text-xs text-muted-foreground'>{t('latestUpdates')}</p>
            </div>
            <div className='grid grid-cols-2 rounded-lg bg-muted p-1'>
              <button className={cn('h-8 rounded-md text-xs font-medium transition-colors', activeTab === 'notice' ? 'bg-background shadow-sm' : 'text-muted-foreground')} onClick={() => setActiveTab('notice')}>
                {t('notice')}
              </button>
              <button className={cn('h-8 rounded-md text-xs font-medium transition-colors', activeTab === 'timeline' ? 'bg-background shadow-sm' : 'text-muted-foreground')} onClick={() => setActiveTab('timeline')}>
                {t('timeline')}
              </button>
            </div>
            {activeTab === 'notice' ? (
              <div className='rounded-lg border border-border bg-card p-3'>
                <div className='flex items-start gap-3'>
                  <Bell className='mt-0.5 size-4 text-muted-foreground' />
                  <div>
                    <div className='font-medium'>{t('connectionWorkspaceLive', { productName })}</div>
                    <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('connectionWorkspaceLiveBody')}</p>
                  </div>
                </div>
              </div>
            ) : (
              <div className='max-h-72 overflow-auto pr-1'>
                {notifications.map((item) => (
                  <div key={item.id} className='flex gap-3 border-b border-border py-3 last:border-0'>
                    <span className={cn('mt-1.5 size-2 rounded-full', item.type === 'success' ? 'bg-success' : item.type === 'warning' ? 'bg-warning' : 'bg-info')} />
                    <div className='min-w-0'>
                      <div className='flex items-center gap-2 font-medium'>
                        <RadioTower className='size-3.5 text-muted-foreground' />
                        {item.title}
                      </div>
                      <p className='mt-1 text-xs leading-5 text-muted-foreground'>{item.body}</p>
                      <div className='mt-1 text-[11px] text-muted-foreground'>{item.time}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>
  )
}
