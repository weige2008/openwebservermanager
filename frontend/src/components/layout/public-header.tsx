import { Link } from '@tanstack/react-router'
import { Menu, X } from 'lucide-react'
import { useEffect, useState } from 'react'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'

import { Button } from '../ui/button'
import { buttonVariants } from '../ui/button'
import { SystemBrand } from './system-brand'
import { ThemeSwitch } from './theme-switch'

export function PublicHeader({ authenticated }: { authenticated: boolean }) {
  const { publicConfig, setupRequired } = useApp()
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

  const entryLabel = authenticated ? '进入控制台' : setupRequired ? '初始化' : '登录'
  const entryTo = authenticated ? '/app' : '/login'
  const publicLinks = publicConfig.nav_links

  return (
    <>
      <header className='pointer-events-none fixed inset-x-0 top-0 z-50'>
        <div
          className={cn(
            'pointer-events-auto mx-auto transition-all duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]',
            scrolled ? 'max-w-[52rem] px-3 pt-3' : 'max-w-7xl px-4 pt-0 md:px-6'
          )}
        >
          <nav
            className={cn(
              'flex items-center justify-between transition-all duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]',
              scrolled
                ? 'h-12 rounded-2xl bg-background/60 pr-1.5 pl-4 shadow-[0_2px_16px_-6px_rgb(0_0_0_/_0.08),0_0_0_0.5px_rgb(0_0_0_/_0.02)] ring-[0.5px] ring-border/50 backdrop-blur-2xl dark:shadow-[0_2px_16px_-6px_rgb(0_0_0_/_0.4)]'
                : 'h-16 px-2'
            )}
          >
            <SystemBrand clickable />

            <div className='hidden items-center gap-0.5 sm:flex'>
              {publicLinks.map((link) => (
                <a
                  key={link.href}
                  href={link.href}
                  target={link.external ? '_blank' : undefined}
                  rel={link.external ? 'noreferrer' : undefined}
                  className='rounded-lg px-3 py-1.5 text-[13px] font-medium text-muted-foreground transition-colors duration-200 hover:text-foreground'
                >
                  {link.title}
                </a>
              ))}
              <div className='mx-2 h-4 w-px bg-border/40' />
              <ThemeSwitch className='size-9' />
              <div className='mx-1 h-4 w-px bg-border/40' />
              <Link
                to={entryTo}
                className={cn(buttonVariants({ variant: 'primary', size: 'sm' }), 'h-8 rounded-lg px-3.5 text-xs font-medium')}
              >
                {entryLabel}
              </Link>
            </div>

            <div className='flex items-center gap-2 sm:hidden'>
              <ThemeSwitch className='size-9' />
              <Button
                type='button'
                variant='ghost'
                size='icon'
                className='size-9'
                onClick={() => setMobileOpen((open) => !open)}
                aria-label='切换导航菜单'
              >
                {mobileOpen ? <X className='size-4' /> : <Menu className='size-4' />}
              </Button>
            </div>
          </nav>
        </div>
      </header>

      <div
        className={cn(
          'fixed inset-0 z-40 bg-background/98 backdrop-blur-2xl transition-all duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] sm:pointer-events-none sm:hidden',
          mobileOpen ? 'pointer-events-auto opacity-100' : 'pointer-events-none opacity-0'
        )}
      >
        <div className='flex h-full flex-col justify-between px-8 pt-20 pb-10'>
          <nav className='flex flex-col gap-1'>
            {publicLinks.map((link, index) => (
              <a
                key={link.href}
                href={link.href}
                target={link.external ? '_blank' : undefined}
                rel={link.external ? 'noreferrer' : undefined}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  'py-3 text-base font-medium tracking-tight text-muted-foreground transition-all duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] hover:text-foreground',
                  mobileOpen ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0'
                )}
                style={{ transitionDelay: mobileOpen ? `${100 + index * 50}ms` : '0ms' }}
              >
                {link.title}
              </a>
            ))}
          </nav>

          <Link
            to={entryTo}
            onClick={() => setMobileOpen(false)}
            className={cn(
              'inline-flex h-10 items-center justify-center rounded-lg bg-foreground text-sm font-medium text-background transition-all duration-500 hover:opacity-90 active:opacity-80',
              mobileOpen ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0'
            )}
            style={{ transitionDelay: mobileOpen ? '250ms' : '0ms' }}
          >
            {authenticated ? '进入控制台' : setupRequired ? '初始化管理员' : '登录控制台'}
          </Link>
        </div>
      </div>
    </>
  )
}
