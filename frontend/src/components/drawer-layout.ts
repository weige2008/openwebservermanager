import { cn } from '@/lib/utils'

export const sideDrawerContentClassName = (className?: string) =>
  cn('flex h-dvh w-full flex-col gap-0 overflow-hidden bg-background p-0 text-foreground shadow-none', className)

export const sideDrawerHeaderClassName = (className?: string) =>
  cn('border-b border-border/70 bg-background/95 px-4 py-3 text-start backdrop-blur supports-[backdrop-filter]:bg-background/80 sm:px-6 sm:py-4', className)

export const sideDrawerFormClassName = (className?: string) =>
  cn('flex min-h-0 flex-1 flex-col gap-6 overflow-y-auto overscroll-contain px-4 py-4 sm:px-6 sm:py-5', className)

export const sideDrawerFooterClassName = (className?: string) =>
  cn('border-t border-border/70 bg-background/95 grid grid-cols-1 gap-2 px-4 py-3 backdrop-blur supports-[backdrop-filter]:bg-background/80 sm:px-6 sm:py-4', className)
