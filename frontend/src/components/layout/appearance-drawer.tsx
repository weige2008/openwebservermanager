import { Radio as RadioPrimitive } from '@base-ui/react/radio'
import { RadioGroup as Radio } from '@base-ui/react/radio-group'
import { CircleCheck, Monitor, Moon, Palette, RotateCcw, Sun } from 'lucide-react'
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
import { defaultAppearance, usePreferencesStore } from '@/stores/preferences-store'
import type { Theme, ThemeContentLayout, ThemeFont, ThemePreset, ThemeRadius, ThemeScale, ThemeSidebarStyle } from '@/types'

import { Button } from '../ui/button'

const Item = RadioPrimitive.Root

const presets: Array<{ value: ThemePreset; label: string; swatches: string[] }> = [
  { value: 'default', label: 'Default', swatches: [] },
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

const themeModes: Array<{ value: Theme; labelKey: string; icon: typeof Sun }> = [
  { value: 'system', labelKey: 'system', icon: Monitor },
  { value: 'light', labelKey: 'light', icon: Sun },
  { value: 'dark', labelKey: 'dark', icon: Moon },
]

const fontOptions: Array<{ value: ThemeFont; labelKey: string; preview?: string }> = [
  { value: 'default', labelKey: 'auto' },
  { value: 'sans', labelKey: 'sans', preview: 'var(--font-sans)' },
  { value: 'serif', labelKey: 'serif', preview: 'var(--font-serif)' },
]

const radiusOptions: Array<{ value: ThemeRadius; label: string; preview: string }> = [
  { value: 'default', label: 'Auto', preview: '1rem' },
  { value: 'none', label: '0', preview: '0' },
  { value: 'sm', label: '0.3', preview: '0.3rem' },
  { value: 'md', label: '0.5', preview: '0.5rem' },
  { value: 'lg', label: '0.75', preview: '0.75rem' },
  { value: 'xl', label: '1.0', preview: '1rem' },
]

const scaleOptions: Array<{ value: ThemeScale; labelKey: string; bars: string[] }> = [
  { value: 'sm', labelKey: 'compact', bars: ['h-1.5', 'h-1.5', 'h-1.5'] },
  { value: 'default', labelKey: 'default', bars: ['h-2', 'h-2', 'h-2'] },
  { value: 'lg', labelKey: 'comfortable', bars: ['h-2.5', 'h-2.5', 'h-2.5'] },
  { value: 'xl', labelKey: 'large', bars: ['h-3', 'h-3', 'h-3'] },
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
          <ThemeConfig />
          <PresetConfig />
          <FontConfig />
          <RadiusConfig />
          <ScaleConfig />
          <ContentLayoutConfig />
          <SidebarConfig />
        </div>

        <SheetFooter className={sideDrawerFooterClassName('grid-cols-1')}>
          <Button variant='destructive' onClick={resetAppearance}>
            <RotateCcw className='size-4' />
            {t('reset')}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}

function SectionTitle({ title, showReset, onReset }: { title: string; showReset?: boolean; onReset?: () => void }) {
  const { t } = useTranslation()

  return (
    <div className='mb-2 flex items-center gap-2 text-sm font-semibold text-muted-foreground'>
      {title}
      {showReset && onReset ? (
        <Button size='icon' variant='secondary' className='size-4' onClick={onReset} aria-label={t('reset')}>
          <RotateCcw className='size-3' />
        </Button>
      ) : null}
    </div>
  )
}

function ThemeConfig() {
  const { t } = useTranslation()
  const theme = usePreferencesStore((state) => state.theme)
  const setTheme = usePreferencesStore((state) => state.setTheme)

  return (
    <OptionSection>
      <SectionTitle title={t('theme')} showReset={theme !== 'system'} onReset={() => setTheme('system')} />
      <Radio value={theme} onValueChange={(value) => setTheme(value as Theme)} className='grid w-full grid-cols-3 gap-4' aria-label={t('theme')}>
        {themeModes.map((mode) => (
          <PreviewItem key={mode.value} value={mode.value} label={t(mode.labelKey)}>
            <ThemePreview icon={mode.icon} mode={mode.value} />
          </PreviewItem>
        ))}
      </Radio>
    </OptionSection>
  )
}

function PresetConfig() {
  const { t } = useTranslation()
  const appearance = usePreferencesStore((state) => state.appearance)
  const setAppearance = usePreferencesStore((state) => state.setAppearance)

  return (
    <OptionSection>
      <SectionTitle
        title={t('colorPreset')}
        showReset={appearance.preset !== defaultAppearance.preset}
        onReset={() => setAppearance({ preset: defaultAppearance.preset })}
      />
      <Radio value={appearance.preset} onValueChange={(value) => setAppearance({ preset: value as ThemePreset })} className='grid w-full grid-cols-4 gap-3' aria-label={t('colorPreset')}>
        {presets.map((preset) => (
          <Item key={preset.value} value={preset.value} className='group flex flex-col items-stretch outline-none' aria-label={t(`preset.${preset.value}`, { defaultValue: preset.label })}>
            <div className='relative h-12 rounded-md ring-1 ring-border transition group-hover:ring-primary/60 group-data-checked:ring-primary group-data-checked:shadow-md group-focus-visible:ring-2'>
              <span
                aria-hidden='true'
                className='absolute inset-0 rounded-md'
                style={{
                  background:
                    preset.value === 'default'
                      ? 'linear-gradient(135deg, var(--background) 0%, var(--muted) 50%, var(--foreground) 100%)'
                      : `linear-gradient(135deg, ${preset.swatches[0]} 0%, ${preset.swatches[1]} 100%)`,
                }}
              />
              <CircleCheck className='absolute top-0 right-0 z-10 hidden size-5 translate-x-1/2 -translate-y-1/2 fill-primary stroke-primary-foreground group-data-checked:block' />
            </div>
            <div className='mt-1.5 truncate text-center text-xs'>{t(`preset.${preset.value}`, { defaultValue: preset.label })}</div>
          </Item>
        ))}
      </Radio>
    </OptionSection>
  )
}

function FontConfig() {
  const { t } = useTranslation()
  const appearance = usePreferencesStore((state) => state.appearance)
  const setAppearance = usePreferencesStore((state) => state.setAppearance)

  return (
    <OptionSection>
      <SectionTitle
        title={t('font')}
        showReset={appearance.font !== defaultAppearance.font}
        onReset={() => setAppearance({ font: defaultAppearance.font })}
      />
      <Radio value={appearance.font} onValueChange={(value) => setAppearance({ font: value as ThemeFont })} className='grid w-full grid-cols-3 gap-4' aria-label={t('font')}>
        {fontOptions.map((option) => (
          <PreviewItem key={option.value} value={option.value} label={t(option.labelKey)}>
            <span className='absolute inset-0 flex items-center justify-center text-lg leading-none font-medium text-foreground' style={option.preview ? { fontFamily: option.preview } : { font: 'inherit', fontSize: '1.125rem' }}>
              Aa
            </span>
          </PreviewItem>
        ))}
      </Radio>
    </OptionSection>
  )
}

function RadiusConfig() {
  const { t } = useTranslation()
  const appearance = usePreferencesStore((state) => state.appearance)
  const setAppearance = usePreferencesStore((state) => state.setAppearance)

  return (
    <OptionSection>
      <SectionTitle
        title={t('borderRadius')}
        showReset={appearance.radius !== defaultAppearance.radius}
        onReset={() => setAppearance({ radius: defaultAppearance.radius })}
      />
      <Radio value={appearance.radius} onValueChange={(value) => setAppearance({ radius: value as ThemeRadius })} className='grid w-full grid-cols-6 gap-2' aria-label={t('borderRadius')}>
        {radiusOptions.map((option) => (
          <PreviewItem key={option.value} value={option.value} label={option.label}>
            <span aria-hidden='true' className='absolute top-2.5 left-2.5 size-3.5 border-t-[1.5px] border-l-[1.5px] border-foreground/70' style={{ borderTopLeftRadius: option.preview }} />
          </PreviewItem>
        ))}
      </Radio>
    </OptionSection>
  )
}

function ScaleConfig() {
  const { t } = useTranslation()
  const appearance = usePreferencesStore((state) => state.appearance)
  const setAppearance = usePreferencesStore((state) => state.setAppearance)

  return (
    <OptionSection>
      <SectionTitle
        title={t('density')}
        showReset={appearance.scale !== defaultAppearance.scale}
        onReset={() => setAppearance({ scale: defaultAppearance.scale })}
      />
      <Radio value={appearance.scale} onValueChange={(value) => setAppearance({ scale: value as ThemeScale })} className='grid w-full grid-cols-4 gap-3' aria-label={t('density')}>
        {scaleOptions.map((option) => (
          <PreviewItem key={option.value} value={option.value} label={t(option.labelKey)}>
            <span className='absolute inset-0 grid content-center gap-1.5 px-3'>
              {option.bars.map((height, index) => (
                <span key={index} className={cn('rounded bg-foreground/70', height)} />
              ))}
            </span>
          </PreviewItem>
        ))}
      </Radio>
    </OptionSection>
  )
}

function ContentLayoutConfig() {
  const { t } = useTranslation()
  const appearance = usePreferencesStore((state) => state.appearance)
  const setAppearance = usePreferencesStore((state) => state.setAppearance)

  return (
    <OptionSection>
      <SectionTitle
        title={t('contentWidth')}
        showReset={appearance.contentLayout !== defaultAppearance.contentLayout}
        onReset={() => setAppearance({ contentLayout: defaultAppearance.contentLayout })}
      />
      <Radio value={appearance.contentLayout} onValueChange={(value) => setAppearance({ contentLayout: value as ThemeContentLayout })} className='grid w-full grid-cols-2 gap-4' aria-label={t('contentWidth')}>
        {contentLayoutOptions.map((option) => (
          <PreviewItem key={option.value} value={option.value} label={t(option.labelKey)}>
            <span className='absolute inset-0 grid place-items-center px-3'>
              <span className={cn('h-7 rounded border border-foreground/40 bg-foreground/10', option.value === 'centered' ? 'w-3/5' : 'w-full')} />
            </span>
          </PreviewItem>
        ))}
      </Radio>
    </OptionSection>
  )
}

function SidebarConfig() {
  const { t } = useTranslation()
  const appearance = usePreferencesStore((state) => state.appearance)
  const setAppearance = usePreferencesStore((state) => state.setAppearance)

  return (
    <OptionSection>
      <SectionTitle
        title={t('sidebarStyle')}
        showReset={appearance.sidebarStyle !== defaultAppearance.sidebarStyle}
        onReset={() => setAppearance({ sidebarStyle: defaultAppearance.sidebarStyle })}
      />
      <Radio value={appearance.sidebarStyle} onValueChange={(value) => setAppearance({ sidebarStyle: value as ThemeSidebarStyle })} className='grid w-full grid-cols-3 gap-4' aria-label={t('sidebarStyle')}>
        {sidebarStyleOptions.map((option) => (
          <PreviewItem key={option.value} value={option.value} label={t(option.labelKey)}>
            <span className='absolute inset-0 p-2'>
              <span className='flex h-full gap-1.5'>
                <span className={cn('w-3 rounded bg-foreground/70', option.value === 'floating' && 'my-1', option.value === 'inset' && 'rounded-r-none')} />
                <span className={cn('flex-1 rounded border border-foreground/25 bg-foreground/10', option.value === 'inset' && 'rounded-l-none')} />
              </span>
            </span>
          </PreviewItem>
        ))}
      </Radio>
    </OptionSection>
  )
}

function PreviewItem({ value, label, children }: { value: string; label: string; children: ReactNode }) {
  return (
    <Item value={value} className='group flex flex-col items-stretch outline-none' aria-label={label}>
      <div className='relative h-12 rounded-md ring-1 ring-border transition group-hover:ring-primary/60 group-data-checked:ring-primary group-data-checked:shadow-md group-focus-visible:ring-2'>
        <CircleCheck className='absolute top-0 right-0 z-10 hidden size-5 translate-x-1/2 -translate-y-1/2 fill-primary stroke-primary-foreground group-data-checked:block' />
        {children}
      </div>
      <div className='mt-1.5 truncate text-center text-xs'>{label}</div>
    </Item>
  )
}

function ThemePreview({ icon: Icon, mode }: { icon: typeof Sun; mode: Theme }) {
  return (
    <span className='absolute inset-0 overflow-hidden rounded-md bg-muted'>
      <span className={cn('absolute inset-y-0 left-0 w-4', mode === 'dark' ? 'bg-foreground/70' : 'bg-foreground/15')} />
      <span className={cn('absolute inset-y-0 right-0 left-4', mode === 'dark' ? 'bg-foreground/20' : 'bg-background')} />
      <Icon className={cn('absolute right-2 bottom-2 size-4', mode === 'dark' ? 'text-background' : 'text-foreground')} />
    </span>
  )
}

function OptionSection({ children }: { children: ReactNode }) {
  return <section>{children}</section>
}
