import { Menu as BaseMenu } from '@base-ui/react/menu'
import { Check, Languages } from 'lucide-react'

import { useApp } from '@/app/app-provider'
import { languageOptions } from '@/lib/i18n'
import { cn } from '@/lib/utils'

import { buttonVariants, type ButtonProps } from '../ui/button'

export function LanguageSwitcher({
  className,
  size = 'icon',
  variant = 'ghost',
}: {
  className?: string
  size?: ButtonProps['size']
  variant?: ButtonProps['variant']
}) {
  const { locale, setLocale, t } = useApp()

  return (
    <BaseMenu.Root modal={false}>
      <BaseMenu.Trigger className={cn(buttonVariants({ variant, size }), 'relative p-0', className)} aria-label={t('changeLanguage')} title={t('changeLanguage')}>
        <Languages className='size-[1.05rem]' />
        <span className='sr-only'>{t('changeLanguage')}</span>
      </BaseMenu.Trigger>
      <BaseMenu.Portal>
        <BaseMenu.Positioner sideOffset={8} align='end'>
          <BaseMenu.Popup className='z-50 grid w-40 gap-1 rounded-xl bg-popover p-1 text-sm text-popover-foreground shadow-md ring-1 ring-foreground/10 outline-none'>
            <div className='px-2 py-1 text-xs text-muted-foreground'>{t('language')}</div>
            {languageOptions.map((option) => (
              <BaseMenu.Item
                key={option.code}
                onClick={() => setLocale(option.code)}
                className='flex h-8 cursor-default items-center gap-2 rounded-lg px-2 text-sm outline-none transition-colors data-[highlighted]:bg-muted'
              >
                <span>{option.label}</span>
                {locale === option.code ? <Check className='ms-auto size-3.5' /> : null}
              </BaseMenu.Item>
            ))}
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>
  )
}
