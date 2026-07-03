import type { ReactNode } from 'react'

import { cn } from '@/lib/utils'

type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'info'

export function Badge({ children, tone = 'neutral', className }: { children: ReactNode; tone?: Tone; className?: string }) {
  return (
    <span
      data-slot='badge'
      className={cn(
        'inline-flex h-5 w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-full border border-transparent px-2 py-0.5 text-xs font-medium whitespace-nowrap transition-all focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50',
        tone === 'neutral' && 'border-border bg-secondary text-secondary-foreground',
        tone === 'success' && 'bg-success/12 text-foreground ring-1 ring-success/25',
        tone === 'warning' && 'bg-warning/15 text-foreground ring-1 ring-warning/25',
        tone === 'danger' && 'bg-destructive/10 text-destructive ring-1 ring-destructive/20',
        tone === 'info' && 'bg-info/12 text-foreground ring-1 ring-info/25',
        className
      )}
    >
      {children}
    </span>
  )
}
