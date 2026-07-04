import { Dialog as SheetPrimitive } from '@base-ui/react/dialog'
import { X } from 'lucide-react'
import type { ComponentProps } from 'react'
import { useTranslation } from 'react-i18next'

import { cn } from '@/lib/utils'

import { Button } from './button'

function Sheet(props: SheetPrimitive.Root.Props) {
  return <SheetPrimitive.Root data-slot='sheet' {...props} />
}

function SheetTrigger(props: SheetPrimitive.Trigger.Props) {
  return <SheetPrimitive.Trigger data-slot='sheet-trigger' {...props} />
}

function SheetClose(props: SheetPrimitive.Close.Props) {
  return <SheetPrimitive.Close data-slot='sheet-close' {...props} />
}

function SheetPortal(props: SheetPrimitive.Portal.Props) {
  return <SheetPrimitive.Portal data-slot='sheet-portal' {...props} />
}

function SheetOverlay({ className, ...props }: SheetPrimitive.Backdrop.Props) {
  return (
    <SheetPrimitive.Backdrop
      data-slot='sheet-overlay'
      className={cn('fixed inset-0 z-[200] bg-black/20 backdrop-blur-sm transition-opacity duration-150 data-ending-style:opacity-0 data-starting-style:opacity-0', className)}
      {...props}
    />
  )
}

function SheetContent({
  className,
  children,
  side = 'right',
  showCloseButton = true,
  ...props
}: SheetPrimitive.Popup.Props & {
  side?: 'top' | 'right' | 'bottom' | 'left'
  showCloseButton?: boolean
}) {
  const { t } = useTranslation()

  return (
    <SheetPortal>
      <SheetOverlay />
      <SheetPrimitive.Popup
        data-slot='sheet-content'
        data-side={side}
        className={cn(
          'fixed z-[200] flex flex-col gap-4 overflow-hidden bg-background bg-clip-padding text-sm text-foreground shadow-2xl outline-none transition duration-200 ease-in-out data-ending-style:opacity-0 data-starting-style:opacity-0',
          side === 'right' && 'inset-y-0 right-0 h-full w-3/4 border-l border-border data-ending-style:translate-x-10 data-starting-style:translate-x-10 sm:max-w-sm',
          side === 'left' && 'inset-y-0 left-0 h-full w-3/4 border-r border-border data-ending-style:-translate-x-10 data-starting-style:-translate-x-10 sm:max-w-sm',
          side === 'top' && 'inset-x-0 top-0 h-auto border-b border-border data-ending-style:-translate-y-10 data-starting-style:-translate-y-10',
          side === 'bottom' && 'inset-x-0 bottom-0 h-auto border-t border-border data-ending-style:translate-y-10 data-starting-style:translate-y-10',
          className
        )}
        {...props}
      >
        {children}
        {showCloseButton ? (
          <SheetPrimitive.Close render={<Button variant='ghost' size='icon-sm' className='absolute top-3 right-3' />}>
            <X className='size-4' />
            <span className='sr-only'>{t('close')}</span>
          </SheetPrimitive.Close>
        ) : null}
      </SheetPrimitive.Popup>
    </SheetPortal>
  )
}

function SheetHeader({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot='sheet-header' className={cn('flex flex-col gap-1 p-4', className)} {...props} />
}

function SheetFooter({ className, ...props }: ComponentProps<'div'>) {
  return <div data-slot='sheet-footer' className={cn('mt-auto flex flex-col gap-2 p-4', className)} {...props} />
}

function SheetTitle({ className, ...props }: SheetPrimitive.Title.Props) {
  return <SheetPrimitive.Title data-slot='sheet-title' className={cn('text-base font-semibold text-foreground', className)} {...props} />
}

function SheetDescription({ className, ...props }: SheetPrimitive.Description.Props) {
  return <SheetPrimitive.Description data-slot='sheet-description' className={cn('text-sm leading-6 text-muted-foreground', className)} {...props} />
}

export { Sheet, SheetTrigger, SheetClose, SheetContent, SheetHeader, SheetFooter, SheetTitle, SheetDescription }
