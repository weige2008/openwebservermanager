import { Link } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'

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
  const app = useApp()
  const { t } = useTranslation()
  const siteName = app.publicConfig.site_name || t('productName')

  const content = (
    <span
      className={cn(
        'inline-flex min-w-0 items-center rounded-md text-sm font-medium transition-colors',
        variant === 'inline' && 'min-h-7 gap-1.5 px-1.5 py-0.5 hover:bg-accent',
        variant === 'auth' && 'gap-2 text-xl',
        className
      )}
    >
      <BrandLogo className={variant === 'auth' ? 'size-9' : 'size-6'} title={siteName} src={app.publicConfig.logo_url} />
      <span className={cn('min-w-0 text-left leading-tight whitespace-normal break-words', variant === 'inline' ? 'max-w-[8.5rem] sm:max-w-[11rem]' : 'max-w-[18rem]')}>
        {siteName}
      </span>
    </span>
  )

  if (!clickable) return content
  return (
    <Link to='/' className='inline-flex min-w-0 transition-opacity hover:opacity-80'>
      {content}
    </Link>
  )
}
