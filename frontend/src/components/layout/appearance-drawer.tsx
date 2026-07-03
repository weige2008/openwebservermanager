import { Dialog as BaseDialog } from '@base-ui/react/dialog'
import { CheckCircle2, Palette, RotateCcw, X } from 'lucide-react'
import { useState } from 'react'
import type { ReactNode } from 'react'

import { useApp } from '@/app/app-provider'
import type { Theme, ThemeContentLayout, ThemeFont, ThemePreset, ThemeRadius, ThemeScale, ThemeSidebarStyle } from '@/types'
import { cn } from '@/lib/utils'

import { Button } from '../ui/button'

const presets: Array<{ value: ThemePreset; label: string; swatches: string[] }> = [
  { value: 'default', label: 'Default', swatches: ['oklch(1 0 0)', 'oklch(0.13 0 0)'] },
  { value: 'underground', label: 'Underground', swatches: ['oklch(0.5315 0.0694 156.19)', 'oklch(0.5748 0.0862 336.52)'] },
  { value: 'rose-garden', label: 'Rose', swatches: ['oklch(0.5827 0.2418 12.23)', 'oklch(0.8131 0.1129 5.67)'] },
  { value: 'lake-view', label: 'Lake', swatches: ['oklch(0.765 0.177 163.22)', 'oklch(0.551 0.0899 200.52)'] },
  { value: 'sunset-glow', label: 'Sunset', swatches: ['oklch(0.5591 0.1882 25.33)', 'oklch(0.7938 0.1248 42.42)'] },
  { value: 'forest-whisper', label: 'Forest', swatches: ['oklch(0.5276 0.1072 182.22)', 'oklch(0.5236 0.0505 250.18)'] },
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
  const app = useApp()
  const [open, setOpen] = useState(false)

  return (
    <BaseDialog.Root open={open} onOpenChange={setOpen}>
      <BaseDialog.Trigger render={<Button size='icon' variant='ghost' className={className} aria-label={app.t('openThemeSettings')} title={app.t('openThemeSettings')} />}>
        <Palette className='size-[1.05rem]' />
      </BaseDialog.Trigger>
      <BaseDialog.Portal>
        <BaseDialog.Backdrop className='fixed inset-0 z-50 bg-black/20 backdrop-blur-sm' />
        <BaseDialog.Popup className='fixed inset-y-0 right-0 z-50 grid w-[min(25rem,calc(100vw-1rem))] grid-rows-[auto_minmax(0,1fr)_auto] border-l border-border bg-popover text-popover-foreground shadow-2xl outline-none'>
          <header className='flex items-start justify-between gap-4 border-b border-border p-4'>
            <div>
              <BaseDialog.Title className='text-base font-semibold'>{app.t('themeSettings')}</BaseDialog.Title>
              <BaseDialog.Description className='mt-1 text-sm leading-6 text-muted-foreground'>{app.t('appearanceDescription')}</BaseDialog.Description>
            </div>
            <BaseDialog.Close render={<Button size='icon-sm' variant='ghost' aria-label={app.t('closeMenu')} />}>
              <X className='size-4' />
            </BaseDialog.Close>
          </header>

          <div className='min-h-0 overflow-y-auto p-4'>
            <div className='grid gap-6'>
              <OptionSection title={app.t('theme')}>
                <div className='grid grid-cols-3 gap-2'>
                  {themeModes.map((mode) => (
                    <ChoiceButton key={mode.value} selected={app.theme === mode.value} onClick={() => app.setTheme(mode.value)}>
                      {app.t(mode.labelKey)}
                    </ChoiceButton>
                  ))}
                </div>
              </OptionSection>

              <OptionSection title={app.t('colorPreset')}>
                <div className='grid grid-cols-3 gap-3'>
                  {presets.map((preset) => (
                    <button
                      key={preset.value}
                      type='button'
                      className={cn('group grid gap-1.5 text-left text-xs outline-none', app.appearance.preset === preset.value && 'text-foreground')}
                      onClick={() => app.setAppearance({ preset: preset.value })}
                    >
                      <span className={cn('relative h-12 rounded-lg ring-1 ring-border transition group-hover:ring-primary/60', app.appearance.preset === preset.value && 'ring-primary shadow-sm')}>
                        <span className='absolute inset-0 rounded-lg' style={{ background: `linear-gradient(135deg, ${preset.swatches[0]}, ${preset.swatches[1]})` }} />
                        {app.appearance.preset === preset.value ? <CheckCircle2 className='absolute -top-2 -right-2 z-10 size-5 fill-primary text-primary-foreground' /> : null}
                      </span>
                      <span className='truncate text-center text-muted-foreground'>{preset.label}</span>
                    </button>
                  ))}
                </div>
              </OptionSection>

              <OptionSection title={app.t('font')}>
                <div className='grid grid-cols-3 gap-2'>
                  {fontOptions.map((option) => (
                    <ChoiceButton key={option.value} selected={app.appearance.font === option.value} onClick={() => app.setAppearance({ font: option.value })}>
                      {app.t(option.labelKey)}
                    </ChoiceButton>
                  ))}
                </div>
              </OptionSection>

              <OptionSection title={app.t('borderRadius')}>
                <div className='grid grid-cols-6 gap-2'>
                  {radiusOptions.map((option) => (
                    <ChoiceButton key={option.value} selected={app.appearance.radius === option.value} onClick={() => app.setAppearance({ radius: option.value })}>
                      {option.label}
                    </ChoiceButton>
                  ))}
                </div>
              </OptionSection>

              <OptionSection title={app.t('density')}>
                <div className='grid grid-cols-4 gap-2'>
                  {scaleOptions.map((option) => (
                    <ChoiceButton key={option.value} selected={app.appearance.scale === option.value} onClick={() => app.setAppearance({ scale: option.value })}>
                      {app.t(option.labelKey)}
                    </ChoiceButton>
                  ))}
                </div>
              </OptionSection>

              <OptionSection title={app.t('contentWidth')}>
                <div className='grid grid-cols-2 gap-2'>
                  {contentLayoutOptions.map((option) => (
                    <ChoiceButton key={option.value} selected={app.appearance.contentLayout === option.value} onClick={() => app.setAppearance({ contentLayout: option.value })}>
                      {app.t(option.labelKey)}
                    </ChoiceButton>
                  ))}
                </div>
              </OptionSection>

              <OptionSection title={app.t('sidebarStyle')}>
                <div className='grid grid-cols-3 gap-2'>
                  {sidebarStyleOptions.map((option) => (
                    <ChoiceButton key={option.value} selected={app.appearance.sidebarStyle === option.value} onClick={() => app.setAppearance({ sidebarStyle: option.value })}>
                      {app.t(option.labelKey)}
                    </ChoiceButton>
                  ))}
                </div>
              </OptionSection>
            </div>
          </div>

          <footer className='border-t border-border p-4'>
            <Button variant='destructive' className='w-full' onClick={app.resetAppearance}>
              <RotateCcw className='size-4' />
              {app.t('reset')}
            </Button>
          </footer>
        </BaseDialog.Popup>
      </BaseDialog.Portal>
    </BaseDialog.Root>
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
