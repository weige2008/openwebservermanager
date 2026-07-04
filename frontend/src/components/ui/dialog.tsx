import { Dialog as BaseDialog } from '@base-ui/react/dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { cn } from '@/lib/utils'

import { Button } from './button'

export function DialogShell({
  open,
  onOpenChange,
  title,
  description,
  children,
  compact,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  description?: string
  children: ReactNode
  compact?: boolean
}) {
  const { t } = useTranslation()

  return (
    <BaseDialog.Root data-slot='dialog' open={open} onOpenChange={onOpenChange}>
      <BaseDialog.Portal>
        <BaseDialog.Backdrop data-slot='dialog-overlay' className='fixed inset-0 isolate z-[200] bg-black/10 duration-100 supports-backdrop-filter:backdrop-blur-xs' />
        <BaseDialog.Popup
          data-slot='dialog-content'
          className={cn(
            'fixed top-1/2 left-1/2 z-[200] grid max-h-[calc(100vh-2rem)] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 grid-rows-[auto_minmax(0,1fr)] gap-4 overflow-hidden rounded-xl bg-popover p-4 text-sm text-popover-foreground ring-1 ring-foreground/10 shadow-md outline-none',
            compact ? 'max-w-xl' : 'max-w-3xl'
          )}
        >
          <header data-slot='dialog-header' className='flex items-start justify-between gap-4'>
            <div className='grid gap-2'>
              <BaseDialog.Title data-slot='dialog-title' className='text-base leading-none font-medium'>{title}</BaseDialog.Title>
              {description ? <BaseDialog.Description data-slot='dialog-description' className='text-sm text-muted-foreground'>{description}</BaseDialog.Description> : null}
            </div>
            <BaseDialog.Close render={<Button size='icon-sm' variant='ghost' aria-label={t('close')}><X className='size-4' /></Button>} />
          </header>
          <div className='-mx-1 min-h-0 overflow-x-hidden overflow-y-auto overscroll-contain px-1 py-1'>{children}</div>
        </BaseDialog.Popup>
      </BaseDialog.Portal>
    </BaseDialog.Root>
  )
}
