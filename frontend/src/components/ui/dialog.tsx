import { Dialog as BaseDialog } from '@base-ui/react/dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'

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
  return (
    <BaseDialog.Root open={open} onOpenChange={onOpenChange}>
      <BaseDialog.Portal>
        <BaseDialog.Backdrop className='fixed inset-0 z-50 bg-black/50' />
        <BaseDialog.Popup
          className={cn(
            'fixed top-1/2 left-1/2 z-50 grid max-h-[calc(100vh-2rem)] w-[calc(100vw-2rem)] -translate-x-1/2 -translate-y-1/2 grid-rows-[auto_minmax(0,1fr)] overflow-hidden rounded-xl border border-border bg-card shadow-2xl outline-none',
            compact ? 'max-w-xl' : 'max-w-3xl'
          )}
        >
          <header className='flex items-start justify-between gap-4 border-b border-border p-4'>
            <div>
              <BaseDialog.Title className='text-lg font-semibold tracking-tight'>{title}</BaseDialog.Title>
              {description ? <BaseDialog.Description className='mt-1 text-sm text-muted-foreground'>{description}</BaseDialog.Description> : null}
            </div>
            <BaseDialog.Close render={<Button size='icon' variant='ghost' aria-label='关闭'><X className='size-4' /></Button>} />
          </header>
          <div className='overflow-auto p-4'>{children}</div>
        </BaseDialog.Popup>
      </BaseDialog.Portal>
    </BaseDialog.Root>
  )
}
