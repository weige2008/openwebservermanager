import { Link } from '@tanstack/react-router'

import { cn } from '@/lib/utils'

export function SystemBrand({ className, clickable = false }: { className?: string; clickable?: boolean }) {
  const content = (
    <span className={cn('inline-flex items-center gap-2.5', className)}>
      <span className='grid size-8 place-items-center rounded-full bg-primary text-primary-foreground shadow-sm'>
        <span className='size-3.5 rounded-sm bg-primary-foreground/90' />
      </span>
      <span className='text-sm font-semibold tracking-tight'>ServerManager</span>
    </span>
  )

  if (!clickable) return content
  return (
    <Link to='/' className='transition-opacity hover:opacity-80'>
      {content}
    </Link>
  )
}
