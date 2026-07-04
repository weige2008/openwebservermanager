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
  const siteName = publicConfig.site_name || 'ServerManager'

  const content = (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md text-sm font-medium transition-colors',
        variant === 'inline' && 'h-7 px-1.5 hover:bg-accent',
        variant === 'auth' && 'gap-2 text-xl',
        className
      )}
    >
      <BrandLogo className={variant === 'auth' ? 'size-9' : 'size-6'} title={siteName} />
      <span className='max-w-[12rem] truncate'>{siteName}</span>
    </span>
  )

  if (!clickable) return content
  return (
    <Link to='/' className='transition-opacity hover:opacity-80'>
      {content}
    </Link>
  )
}
