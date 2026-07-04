import { Menu as BaseMenu } from '@base-ui/react/menu'
import { Check, Monitor, Moon, Sun } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { cn } from '@/lib/utils'
import { usePreferencesStore } from '@/stores/preferences-store'
import type { Theme } from '@/types'

import { buttonVariants, type ButtonProps } from '../ui/button'

const themeOptions: Array<{ value: Theme; labelKey: string; icon: typeof Sun }> = [
  { value: 'system', labelKey: 'system', icon: Monitor },
  { value: 'light', labelKey: 'light', icon: Sun },
  { value: 'dark', labelKey: 'dark', icon: Moon },
]

function readSystemTheme() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function ThemeSwitch({
  className,
  size = 'icon',
  variant = 'ghost',
}: {
  className?: string
  size?: ButtonProps['size']
  variant?: ButtonProps['variant']
}) {
  const { t } = useTranslation()
  const theme = usePreferencesStore((state) => state.theme)
  const setTheme = usePreferencesStore((state) => state.setTheme)
  const [systemTheme, setSystemTheme] = useState(readSystemTheme)
  const resolvedTheme = theme === 'system' ? systemTheme : theme

  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => setSystemTheme(media.matches ? 'dark' : 'light')
    media.addEventListener('change', onChange)
    return () => media.removeEventListener('change', onChange)
  }, [])

  return (
    <BaseMenu.Root modal={false}>
      <BaseMenu.Trigger className={cn(buttonVariants({ variant, size }), 'relative p-0', className)} aria-label={t('theme')} title={t('theme')}>
        <Sun className='size-[1.05rem] scale-100 rotate-0 transition-all dark:scale-0 dark:-rotate-90' />
        <Moon className='absolute size-[1.05rem] scale-0 rotate-90 transition-all dark:scale-100 dark:rotate-0' />
        <span className='sr-only'>{t('theme')}</span>
      </BaseMenu.Trigger>
      <BaseMenu.Portal>
        <BaseMenu.Positioner sideOffset={8} align='end' className='z-[240]'>
          <BaseMenu.Popup className='z-[240] grid w-40 gap-1 rounded-xl bg-popover p-1 text-sm text-popover-foreground shadow-md ring-1 ring-foreground/10 outline-none'>
            <div className='px-2 py-1 text-xs text-muted-foreground'>{t('theme')}</div>
            {themeOptions.map((option) => {
              const Icon = option.icon
              const selected = theme === option.value
              return (
                <BaseMenu.Item
                  key={option.value}
                  onClick={() => setTheme(option.value)}
                  className='flex h-8 cursor-default items-center gap-2 rounded-lg px-2 text-sm outline-none transition-colors data-[highlighted]:bg-muted'
                >
                  <Icon className='size-4' />
                  <span>{t(option.labelKey)}</span>
                  {selected ? <Check className='ms-auto size-3.5' /> : null}
                </BaseMenu.Item>
              )
            })}
            <BaseMenu.Separator className='-mx-1 my-1 h-px bg-border' />
            <div className='px-2 py-1 text-xs text-muted-foreground'>
              {t('current')}: {resolvedTheme === 'dark' ? t('dark') : t('light')}
            </div>
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>
  )
}
