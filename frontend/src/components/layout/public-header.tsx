import { Link } from '@tanstack/react-router'
import { Moon, Sun } from 'lucide-react'
import { useEffect, useState } from 'react'

import { useApp } from '@/app/app-provider'
import { cn } from '@/lib/utils'

import { Button } from '../ui/button'
import { buttonVariants } from '../ui/button'
import { SystemBrand } from './system-brand'

export function PublicHeader({ authenticated }: { authenticated: boolean }) {
  const { setupRequired, theme, setTheme } = useApp()
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 18)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const entryLabel = authenticated ? '进入控制台' : setupRequired ? '初始化' : '登录'

  return (
    <header className='pointer-events-none fixed inset-x-0 top-0 z-40'>
      <nav
        className={cn(
          'pointer-events-auto mx-auto flex items-center justify-between transition-all duration-500',
          scrolled
            ? 'mt-3 h-12 w-[min(52rem,calc(100%-1.5rem))] rounded-2xl border border-border/80 bg-background/75 pr-1.5 pl-4 shadow-sm backdrop-blur-2xl'
            : 'h-16 w-[min(72rem,calc(100%-2rem))] px-2'
        )}
      >
        <SystemBrand clickable />
        <div className='hidden items-center gap-1 sm:flex'>
          <a className='rounded-md px-3 py-1.5 text-[13px] font-medium text-muted-foreground hover:text-foreground' href='#features'>能力</a>
          <a className='rounded-md px-3 py-1.5 text-[13px] font-medium text-muted-foreground hover:text-foreground' href='#security'>安全</a>
          <a className='rounded-md px-3 py-1.5 text-[13px] font-medium text-muted-foreground hover:text-foreground' href='#workflow'>流程</a>
        </div>
        <div className='flex items-center gap-2'>
          <Button size='icon-sm' variant='outline' title='切换主题' onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
            {theme === 'dark' ? <Sun className='size-4' /> : <Moon className='size-4' />}
          </Button>
          <Link to={authenticated ? '/app' : '/login'} className={buttonVariants({ variant: 'primary' })}>{entryLabel}</Link>
        </div>
      </nav>
    </header>
  )
}
