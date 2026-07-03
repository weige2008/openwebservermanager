import { CheckCircle2, Palette, RotateCcw } from 'lucide-react'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import {
  sideDrawerContentClassName,
  sideDrawerFooterClassName,
  sideDrawerFormClassName,
  sideDrawerHeaderClassName,
} from '@/components/drawer-layout'
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet'
import { cn } from '@/lib/utils'
import { usePreferencesStore } from '@/stores/preferences-store'
import type { Theme, ThemeContentLayout, ThemeFont, ThemePreset, ThemeRadius, ThemeScale, ThemeSidebarStyle } from '@/types'

import { Button } from '../ui/button'

const presets: Array<{ value: ThemePreset; label: string; swatches: string[] }> = [
  { value: 'default', label: 'Default', swatches: ['oklch(0.13 0 0)', 'oklch(0.95 0 0)'] },
  { value: 'anthropic', label: 'Anthropic', swatches: ['oklch(0.984 0.005 95)', 'oklch(0.685 0.142 38)'] },
  { value: 'simple-large', label: 'Simple Large-font', swatches: ['oklch(0.15 0 0)', 'oklch(0.99 0 0)'] },
  { value: 'underground', label: 'Underground', swatches: ['oklch(0.5315 0.0694 156.19)', 'oklch(0.5748 0.0862 336.52)'] },
  { value: 'rose-garden', label: 'Rose Garden', swatches: ['oklch(0.5827 0.2418 12.23)', 'oklch(0.8131 0.1129 5.67)'] },
  { value: 'lake-view', label: 'Lake View', swatches: ['oklch(0.765 0.177 163.22)', 'oklch(0.551 0.0899 200.52)'] },
  { value: 'sunset-glow', label: 'Sunset Glow', swatches: ['oklch(0.5591 0.1882 25.33)', 'oklch(0.7938 0.1248 42.42)'] },
  { value: 'forest-whisper', label: 'Forest Whisper', swatches: ['oklch(0.5276 0.1072 182.22)', 'oklch(0.5236 0.0505 250.18)'] },
  { value: 'ocean-breeze', label: 'Ocean Breeze', swatches: ['oklch(0.5461 0.2152 262.88)', 'oklch(0.5854 0.2041 277.12)'] },
  { value: 'lavender-dream', label: 'Lavender Dream', swatches: ['oklch(0.5709 0.1808 306.89)', 'oklch(0.811 0.0589 201.14)'] },
]

const themeModes: Array<{ value: Theme; labelKey: string }> = [
  { value: 'system', labelKey: 'system' },
  { value: 'light', labelKey: 'light' },
  { value: 'dark', labelKey: 'dark' },
]

const fontOptions: Array<{ value: ThemeFont; labelKey: string }> = [
  { value: 'default', labelKey: 'auto' },
  { value: 'sans', labelKey: 'sans' },
  { value: 'serif', labelKey: 'serif' },
]

const radiusOptions: Array<{ value: ThemeRadius; label: string }> = [
  { value: 'default', label: 'Auto' },
  { value: 'none', label: '0' },
  { value: 'sm', label: '0.3' },
  { value: 'md', label: '0.5' },
  { value: 'lg', label: '0.75' },
  { value: 'xl', label: '1.0' },
]

const scaleOptions: Array<{ value: ThemeScale; labelKey: string }> = [
  { value: 'sm', labelKey: 'compact' },
  { value: 'default', labelKey: 'default' },
  { value: 'lg', labelKey: 'comfortable' },
  { value: 'xl', labelKey: 'large' },
]

const contentLayoutOptions: Array<{ value: ThemeContentLayout; labelKey: string }> = [
  { value: 'full', labelKey: 'fullWidth' },
  { value: 'centered', labelKey: 'centered' },
]

const sidebarStyleOptions: Array<{ value: ThemeSidebarStyle; labelKey: string }> = [
  { value: 'default', labelKey: 'default' },
  { value: 'inset', labelKey: 'inset' },
  { value: 'floating', labelKey: 'floating' },
]

export function AppearanceDrawer({ className }: { className?: string }) {
  const { t } = useTranslation()
  const theme = usePreferencesStore((state) => state.theme)
  const appearance = usePreferencesStore((state) => state.appearance)
  const setTheme = usePreferencesStore((state) => state.setTheme)
  const setAppearance = usePreferencesStore((state) => state.setAppearance)
  const resetAppearance = usePreferencesStore((state) => state.resetAppearance)

  return (
    <Sheet>
      <SheetTrigger render={<Button size='icon' variant='ghost' className={className} aria-label={t('openThemeSettings')} title={t('openThemeSettings')} />}>
        <Palette className='size-[1.05rem]' />
      </SheetTrigger>
      <SheetContent className={sideDrawerContentClassName('sm:max-w-md')}>
        <SheetHeader className={sideDrawerHeaderClassName()}>
          <SheetTitle>{t('themeSettings')}</SheetTitle>
          <SheetDescription>{t('appearanceDescription')}</SheetDescription>
        </SheetHeader>

        <div className={sideDrawerFormClassName()}>
          <OptionSection title={t('theme')}>
            <div className='grid grid-cols-3 gap-2'>
              {themeModes.map((mode) => (
                <ChoiceButton key={mode.value} selected={theme === mode.value} onClick={() => setTheme(mode.value)}>
                  {t(mode.labelKey)}
                </ChoiceButton>
              ))}
            </div>
          </OptionSection>

          <OptionSection title={t('colorPreset')}>
            <div className='grid grid-cols-3 gap-3'>
              {presets.map((preset) => (
                <button
                  key={preset.value}
                  type='button'
                  className={cn('group grid gap-1.5 text-left text-xs outline-none', appearance.preset === preset.value && 'text-foreground')}
                  onClick={() => setAppearance({ preset: preset.value })}
                >
                  <span className={cn('relative h-12 rounded-lg ring-1 ring-border transition group-hover:ring-primary/60', appearance.preset === preset.value && 'ring-primary shadow-sm')}>
                    <span className='absolute inset-0 rounded-lg' style={{ background: `linear-gradient(135deg, ${preset.swatches[0]}, ${preset.swatches[1]})` }} />
                    {appearance.preset === preset.value ? <CheckCircle2 className='absolute -top-2 -right-2 z-10 size-5 fill-primary text-primary-foreground' /> : null}
                  </span>
                  <span className='truncate text-center text-muted-foreground'>{preset.label}</span>
                </button>
              ))}
            </div>
          </OptionSection>

          <OptionSection title={t('font')}>
            <div className='grid grid-cols-3 gap-2'>
              {fontOptions.map((option) => (
                <ChoiceButton key={option.value} selected={appearance.font === option.value} onClick={() => setAppearance({ font: option.value })}>
                  {t(option.labelKey)}
                </ChoiceButton>
              ))}
            </div>
          </OptionSection>

          <OptionSection title={t('borderRadius')}>
            <div className='grid grid-cols-6 gap-2'>
              {radiusOptions.map((option) => (
                <ChoiceButton key={option.value} selected={appearance.radius === option.value} onClick={() => setAppearance({ radius: option.value })}>
                  {option.label}
                </ChoiceButton>
              ))}
            </div>
          </OptionSection>

          <OptionSection title={t('density')}>
            <div className='grid grid-cols-4 gap-2'>
              {scaleOptions.map((option) => (
                <ChoiceButton key={option.value} selected={appearance.scale === option.value} onClick={() => setAppearance({ scale: option.value })}>
                  {t(option.labelKey)}
                </ChoiceButton>
              ))}
            </div>
          </OptionSection>

          <OptionSection title={t('contentWidth')}>
            <div className='grid grid-cols-2 gap-2'>
              {contentLayoutOptions.map((option) => (
                <ChoiceButton key={option.value} selected={appearance.contentLayout === option.value} onClick={() => setAppearance({ contentLayout: option.value })}>
                  {t(option.labelKey)}
                </ChoiceButton>
              ))}
            </div>
          </OptionSection>

          <OptionSection title={t('sidebarStyle')}>
            <div className='grid grid-cols-3 gap-2'>
              {sidebarStyleOptions.map((option) => (
                <ChoiceButton key={option.value} selected={appearance.sidebarStyle === option.value} onClick={() => setAppearance({ sidebarStyle: option.value })}>
                  {t(option.labelKey)}
                </ChoiceButton>
              ))}
            </div>
          </OptionSection>
        </div>

        <SheetFooter className={sideDrawerFooterClassName()}>
          <Button variant='destructive' className='w-full' onClick={resetAppearance}>
            <RotateCcw className='size-4' />
            {t('reset')}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

function OptionSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section>
      <h3 className='mb-2 text-sm font-semibold text-muted-foreground'>{title}</h3>
      {children}
    </section>
  )
}

function ChoiceButton({ selected, onClick, children }: { selected: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type='button'
      onClick={onClick}
      className={cn(
        'grid h-10 place-items-center rounded-lg border border-border bg-background px-2 text-xs font-medium text-muted-foreground outline-none transition hover:border-primary/60 hover:text-foreground',
        selected && 'border-primary bg-primary text-primary-foreground shadow-sm hover:text-primary-foreground'
      )}
    >
      {children}
    </button>
  )
}
