import { Menu as BaseMenu } from '@base-ui/react/menu'
import { Check, Monitor, Moon, Sun } from 'lucide-react'

import { useApp } from '@/app/app-provider'
import type { Theme } from '@/types'
import { cn } from '@/lib/utils'

import { buttonVariants, type ButtonProps } from '../ui/button'

const themeOptions: Array<{ value: Theme; label: string; icon: typeof Sun }> = [
  { value: 'system', label: '系统', icon: Monitor },
  { value: 'light', label: '浅色', icon: Sun },
  { value: 'dark', label: '深色', icon: Moon },
]

export function ThemeSwitch({
  className,
  size = 'icon',
  variant = 'ghost',
}: {
  className?: string
  size?: ButtonProps['size']
  variant?: ButtonProps['variant']
}) {
  const { theme, resolvedTheme, setTheme } = useApp()

  return (
    <BaseMenu.Root modal={false}>
      <BaseMenu.Trigger
        className={cn(buttonVariants({ variant, size }), 'relative p-0', className)}
        aria-label='切换主题'
        title='切换主题'
      >
        <Sun className='size-[1.05rem] scale-100 rotate-0 transition-all dark:scale-0 dark:-rotate-90' />
        <Moon className='absolute size-[1.05rem] scale-0 rotate-90 transition-all dark:scale-100 dark:rotate-0' />
        <span className='sr-only'>切换主题</span>
      </BaseMenu.Trigger>
      <BaseMenu.Portal>
        <BaseMenu.Positioner sideOffset={8} align='end'>
          <BaseMenu.Popup className='z-50 grid w-40 gap-1 rounded-xl bg-popover p-1 text-sm text-popover-foreground shadow-md ring-1 ring-foreground/10 outline-none'>
            <div className='px-2 py-1 text-xs text-muted-foreground'>主题</div>
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
                  <span>{option.label}</span>
                  {selected ? <Check className='ms-auto size-3.5' /> : null}
                </BaseMenu.Item>
              )
            })}
            <BaseMenu.Separator className='-mx-1 my-1 h-px bg-border' />
            <div className='px-2 py-1 text-xs text-muted-foreground'>当前：{resolvedTheme === 'dark' ? '深色' : '浅色'}</div>
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>
  )
}
