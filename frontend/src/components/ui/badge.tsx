import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info'

export function Badge({ children, tone = 'neutral', className }: { children: ReactNode; tone?: Tone; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex h-6 items-center rounded-md border px-2 text-xs font-medium',
        tone === 'neutral' && 'border-border bg-muted text-foreground',
        tone === 'success' && 'border-success/35 bg-success/12 text-foreground',
        tone === 'warning' && 'border-warning/35 bg-warning/15 text-foreground',
        tone === 'danger' && 'border-destructive/35 bg-destructive/12 text-foreground',
        tone === 'info' && 'border-info/35 bg-info/12 text-foreground',
        className
      )}
    >
      {children}
    </span>
  )
}
