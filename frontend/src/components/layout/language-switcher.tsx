import { Menu as BaseMenu } from '@base-ui/react/menu'
import { Check, Languages } from 'lucide-react'
import { useCallback } from 'react'
import { useTranslation } from 'react-i18next'

import { INTERFACE_LANGUAGE_OPTIONS, normalizeInterfaceLanguage } from '@/i18n/languages'
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
  const { i18n, t } = useTranslation()
  const currentLanguage = normalizeInterfaceLanguage(i18n.language)
  const handleChangeLanguage = useCallback((code: string) => {
    void i18n.changeLanguage(code)
  }, [i18n])

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
            {INTERFACE_LANGUAGE_OPTIONS.map((option) => (
              <BaseMenu.Item
                key={option.code}
                onClick={() => handleChangeLanguage(option.code)}
                className='flex h-8 cursor-default items-center gap-2 rounded-lg px-2 text-sm outline-none transition-colors data-[highlighted]:bg-muted'
              >
                <span>{option.label}</span>
                {currentLanguage === option.code ? <Check className='ms-auto size-3.5' /> : null}
              </BaseMenu.Item>
            ))}
          </BaseMenu.Popup>
        </BaseMenu.Positioner>
      </BaseMenu.Portal>
    </BaseMenu.Root>
  )
}
