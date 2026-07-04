import { Link } from '@tanstack/react-router'
import { Menu, X } from 'lucide-react'
import { useEffect, useState } from 'react'

import { useApp } from '@/app/app-provider'
import { resolvePublicHref } from '@/lib/public-navigation'
import { cn } from '@/lib/utils'

import { Button } from '../ui/button'
import { buttonVariants } from '../ui/button'
import { LanguageSwitcher } from './language-switcher'
import { NotificationButton } from './notification-button'
import { SystemBrand } from './system-brand'
import { ThemeSwitch } from './theme-switch'

export function PublicHeader({ authenticated }: { authenticated: boolean }) {
  const { publicConfig, setupRequired, t } = useApp()
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    document.body.style.overflow = mobileOpen ? 'hidden' : ''
    return () => {
      document.body.style.overflow = ''
    }
  }, [mobileOpen])

  const entryLabel = authenticated ? t('enterConsole') : setupRequired ? t('initialize') : t('signIn')
  const entryTo = authenticated ? '/app' : '/login'
  const publicLinks = publicConfig.nav_links

  return (
    <>
      <header className='fixed inset-x-0 top-0 isolate z-[100] pointer-events-auto'>
        <div
          className={cn(
            'mx-auto transition-all duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]',
            scrolled ? 'max-w-5xl px-3 pt-3' : 'max-w-7xl px-4 pt-3 md:px-6'
          )}
        >
          <nav
            className={cn(
              'relative z-[101] flex min-w-0 items-center justify-between overflow-hidden rounded-2xl border border-border/45 bg-background/82 shadow-[0_10px_32px_-18px_rgb(15_23_42_/_0.45)] backdrop-blur-2xl transition-all duration-700 ease-[cubic-bezier(0.16,1,0.3,1)] dark:bg-background/72',
              scrolled
                ? 'h-12 pr-1.5 pl-4'
                : 'h-14 px-3 md:h-16 md:px-4'
            )}
          >
            <div className='min-w-0 flex-1 pr-2'>
              <SystemBrand clickable className='w-full max-w-full' />
            </div>

            <div className='hidden shrink-0 items-center gap-0.5 lg:flex'>
              {publicLinks.map((link) => (
                <a
                  key={link.href}
                  href={link.external ? link.href : resolvePublicHref(link.href)}
                  target={link.external ? '_blank' : undefined}
                  rel={link.external ? 'noreferrer' : undefined}
                  className='rounded-lg px-3 py-1.5 text-[13px] font-medium text-muted-foreground transition-colors duration-200 hover:text-foreground'
                >
                  {t(link.title)}
                </a>
              ))}
              <div className='mx-2 h-4 w-px bg-border/40' />
              <LanguageSwitcher className='size-9' />
              <ThemeSwitch className='size-9' />
              <NotificationButton className='size-9' />
              <div className='mx-1 h-4 w-px bg-border/40' />
              <Link to={entryTo} className={cn(buttonVariants({ variant: 'primary', size: 'sm' }), 'h-8 rounded-lg px-3.5 text-xs font-medium')}>
                {entryLabel}
              </Link>
            </div>

            <div className='flex shrink-0 items-center gap-1 lg:hidden'>
              <LanguageSwitcher className='size-9' />
              <ThemeSwitch className='size-9' />
              <NotificationButton className='size-9' />
              <Button type='button' variant='ghost' size='icon' className='size-9' onClick={() => setMobileOpen((open) => !open)} aria-label={t('toggleNavigation')}>
                {mobileOpen ? <X className='size-4' /> : <Menu className='size-4' />}
              </Button>
            </div>
          </nav>
        </div>
      </header>

      <div
        className={cn(
          'fixed inset-0 z-[110] bg-background/98 backdrop-blur-2xl transition-all duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] lg:pointer-events-none lg:hidden',
          mobileOpen ? 'pointer-events-auto opacity-100' : 'pointer-events-none opacity-0'
        )}
        aria-hidden={!mobileOpen}
      >
        <div className='flex h-full flex-col justify-between px-8 pt-6 pb-10'>
          <div>
            <div className='flex h-10 items-center justify-between'>
              <SystemBrand clickable />
              <Button type='button' variant='ghost' size='icon' className='size-9' onClick={() => setMobileOpen(false)} aria-label={t('closeMenu')}>
                <X className='size-4' />
              </Button>
            </div>

            <nav className='mt-10 flex flex-col gap-1'>
              {publicLinks.map((link, index) => (
                <a
                  key={link.href}
                  href={link.external ? link.href : resolvePublicHref(link.href)}
                  target={link.external ? '_blank' : undefined}
                  rel={link.external ? 'noreferrer' : undefined}
                  onClick={() => setMobileOpen(false)}
                  className={cn(
                    'py-3 text-base font-medium tracking-tight text-muted-foreground transition-all duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] hover:text-foreground',
                    mobileOpen ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0'
                  )}
                  style={{ transitionDelay: mobileOpen ? `${100 + index * 50}ms` : '0ms' }}
                >
                  {t(link.title)}
                </a>
              ))}
            </nav>
          </div>

          <Link
            to={entryTo}
            onClick={() => setMobileOpen(false)}
            className={cn(
              'inline-flex h-10 items-center justify-center rounded-lg bg-foreground text-sm font-medium text-background transition-all duration-500 hover:opacity-90 active:opacity-80',
              mobileOpen ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0'
            )}
            style={{ transitionDelay: mobileOpen ? '250ms' : '0ms' }}
          >
            {authenticated ? t('enterConsole') : setupRequired ? t('initializeAdmin') : t('signInConsole')}
          </Link>
        </div>
      </div>
    </>
  )
}
