import { Link } from '@tanstack/react-router'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'

import { BrandLogo } from './brand-logo'

export function SystemBrand({
  className,
  clickable = false,
  variant = 'inline',
}: {
  className?: string
  clickable?: boolean
  variant?: 'inline' | 'auth'
}) {
  const { publicConfig } = useApp()
  const siteName = publicConfig.site_name || 'openwebservermanager'

  const content = (
    <span
      className={cn(
        'inline-flex max-w-full min-w-0 items-center gap-1.5 overflow-hidden rounded-md text-sm font-medium transition-colors',
        variant === 'inline' && 'h-7 px-1.5 hover:bg-accent',
        variant === 'auth' && 'gap-2 text-xl',
        className
      )}
    >
      <BrandLogo className={variant === 'auth' ? 'size-9' : 'size-6'} title={siteName} />
      <span className='min-w-0 flex-1 truncate'>{siteName}</span>
    </span>
  )

  if (!clickable) return content
  return (
    <Link to='/' className='inline-flex max-w-full min-w-0 shrink overflow-hidden transition-opacity hover:opacity-80'>
      {content}
    </Link>
  )
}
