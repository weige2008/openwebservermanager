import { Menu as BaseMenu } from '@base-ui/react/menu'
import { useQuery } from '@tanstack/react-query'
import { Bell, RadioTower } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { apiRequest } from '@/lib/api'
import { cn } from '@/lib/utils'
import { useNotificationStore } from '@/stores/notification-store'

import { Badge } from '../ui/badge'
import { buttonVariants, type ButtonProps } from '../ui/button'

interface NotificationItem {
  id: string
  type: 'success' | 'warning' | 'danger' | 'info' | string
  category?: string
  title?: string
  body?: string
  title_key?: string
  body_key?: string
  metadata?: Record<string, unknown>
  created_at?: string
}

export function NotificationButton({
  className,
  size = 'icon',
  variant = 'ghost',
}: {
  className?: string
  size?: ButtonProps['size']
  variant?: ButtonProps['variant']
}) {
  const { auth, data } = useApp()
  const { t } = useTranslation()
  const productName = t('productName')
  const [activeTab, setActiveTab] = useState<'notice' | 'timeline'>('notice')
  const readKeys = useNotificationStore((state) => state.readKeys)
  const markRead = useNotificationStore((state) => state.markRead)
  const notificationQuery = useQuery({
    queryKey: ['notifications'],
    queryFn: () => apiRequest<{ items: NotificationItem[]; generated_at: string }>('/api/notifications'),
    enabled: Boolean(auth),
    refetchInterval: 30000,
    retry: false,
  })

  const fallbackNotifications = useMemo<NotificationItem[]>(() => {
    const gatewayReady = Boolean(data.guacd?.address)
    return [
      {
        id: `gateway:${gatewayReady ? 'online' : 'offline'}`,
        type: gatewayReady ? 'success' : 'warning',
        title_key: gatewayReady ? 'rdpGatewayOnline' : 'rdpGatewayOffline',
        body: gatewayReady ? data.guacd?.address || '' : t('rdpGatewayOfflineBody'),
        created_at: new Date().toISOString(),
      },
      {
        id: 'audit',
        type: 'info',
        title_key: 'sessionAuditEnabled',
        body_key: 'sessionAuditEnabledBody',
        created_at: new Date().toISOString(),
      },
    ]
  }, [data.guacd?.address, t])
  const notifications = auth && notificationQuery.data?.items?.length ? notificationQuery.data.items : fallbackNotifications

  const noticeKey = 'notice:connection-workspace'
  const notificationKeys = useMemo(() => [noticeKey, ...notifications.map((item) => `timeline:${item.id}`)], [notifications])
  const unreadCount = notificationKeys.filter((key) => !readKeys.includes(key)).length
  const renderNotificationText = (key: string | undefined, fallback = '', metadata?: Record<string, unknown>) =>
    key ? t(key, { defaultValue: fallback || key, ...(metadata || {}) }) : fallback

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
                    <span className={cn('mt-1.5 size-2 rounded-full', item.type === 'success' ? 'bg-success' : item.type === 'warning' ? 'bg-warning' : item.type === 'danger' ? 'bg-danger' : 'bg-info')} />
                    <div className='min-w-0'>
                      <div className='flex items-center gap-2 font-medium'>
                        <RadioTower className='size-3.5 text-muted-foreground' />
                        {renderNotificationText(item.title_key, item.title, item.metadata)}
                      </div>
                      <p className='mt-1 text-xs leading-5 text-muted-foreground'>{renderNotificationText(item.body_key, item.body, item.metadata)}</p>
                      <div className='mt-1 text-[11px] text-muted-foreground'>{formatNotificationTime(item.created_at, t('today'))}</div>
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

function formatNotificationTime(value: string | undefined, fallback: string) {
  if (!value) return fallback
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return fallback
  return new Intl.DateTimeFormat(undefined, {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date)
}
