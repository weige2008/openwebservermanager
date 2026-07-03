import { Link } from '@tanstack/react-router'

import { cn } from '@/lib/utils'

export function SystemBrand({
  className,
  clickable = false,
  variant = 'inline',
}: {
  className?: string
  clickable?: boolean
  variant?: 'inline' | 'auth'
}) {
  const content = (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md text-sm font-medium transition-colors',
        variant === 'inline' && 'h-7 px-1.5 hover:bg-accent',
        variant === 'auth' && 'gap-2 text-xl',
        className
      )}
    >
      <span className={cn('grid place-items-center overflow-hidden rounded-md bg-primary text-primary-foreground shadow-sm', variant === 'auth' ? 'size-8 rounded-full' : 'size-5')}>
        <span className={cn('rounded-sm bg-primary-foreground/90', variant === 'auth' ? 'size-3.5' : 'size-2.5')} />
      </span>
      <span className={cn('max-w-[12rem] truncate', variant === 'auth' ? 'font-medium' : 'font-medium')}>ServerManager</span>
    </span>
  )

  if (!clickable) return content
  return (
    <Link to='/' className='transition-opacity hover:opacity-80'>
      {content}
    </Link>
  )
}
