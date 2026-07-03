import type { HTMLAttributes, ReactNode } from 'react'

import { cn } from '@/lib/utils'

export function Card({ className, size = 'default', ...props }: HTMLAttributes<HTMLDivElement> & { size?: 'default' | 'sm' }) {
  return (
    <div
      data-slot='card'
      data-size={size}
      className={cn(
        'group/card flex flex-col gap-4 overflow-hidden rounded-xl bg-card py-4 text-sm text-card-foreground ring-1 ring-foreground/10 has-data-[slot=card-footer]:pb-0 data-[size=sm]:gap-3 data-[size=sm]:py-3',
        className
      )}
      {...props}
    />
  )
}

export function CardHeader({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      data-slot='card-header'
      className={cn(
        'grid grid-cols-[minmax(0,1fr)_auto] auto-rows-min items-start gap-1 px-4 group-data-[size=sm]/card:px-3',
        className
      )}
      {...props}
    />
  )
}

export function CardTitle({ className, ...props }: HTMLAttributes<HTMLHeadingElement>) {
  return <h2 data-slot='card-title' className={cn('text-base leading-snug font-medium group-data-[size=sm]/card:text-sm', className)} {...props} />
}

export function CardDescription({ className, ...props }: HTMLAttributes<HTMLParagraphElement>) {
  return <p data-slot='card-description' className={cn('text-sm text-muted-foreground', className)} {...props} />
}

export function CardAction({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div data-slot='card-action' className={cn('col-start-2 row-span-2 row-start-1 self-start justify-self-end', className)} {...props} />
}

export function CardContent({ className, children }: { className?: string; children: ReactNode }) {
  return <div data-slot='card-content' className={cn('px-4 group-data-[size=sm]/card:px-3', className)}>{children}</div>
}

export function CardFooter({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div data-slot='card-footer' className={cn('flex items-center border-t bg-muted/50 p-4 group-data-[size=sm]/card:p-3', className)} {...props} />
}
