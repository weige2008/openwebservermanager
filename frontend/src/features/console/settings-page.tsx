import { Monitor, Moon, RotateCcw, Sun, UserCircle } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { CardStaggerContainer, CardStaggerItem, StaggerContainer, StaggerItem } from '@/components/page-transition'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Field, Select } from '@/components/ui/field'
import { AboutContent } from '@/features/about/about-page'
import { INTERFACE_LANGUAGE_OPTIONS } from '@/i18n/languages'
import { formatDate } from '@/lib/utils'
import type { Locale, Theme, ThemeContentLayout, ThemeFont, ThemePreset, ThemeRadius, ThemeScale, ThemeSidebarStyle } from '@/types'

const presetOptions: Array<{ value: ThemePreset; label: string }> = [
  { value: 'default', label: 'Default' },
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'simple-large', label: 'Simple Large-font' },
  { value: 'underground', label: 'Underground' },
  { value: 'rose-garden', label: 'Rose Garden' },
  { value: 'lake-view', label: 'Lake View' },
  { value: 'sunset-glow', label: 'Sunset Glow' },
  { value: 'forest-whisper', label: 'Forest Whisper' },
  { value: 'ocean-breeze', label: 'Ocean Breeze' },
  { value: 'lavender-dream', label: 'Lavender Dream' },
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

export function SettingsPage() {
  const app = useApp()
  const { t } = useTranslation()
  const activeSessions = app.data.sessions.filter((session) => session.status === 'active').length
  const username = app.auth?.username || 'admin'
  const initials = username.slice(0, 2).toUpperCase()

  return (
    <CardStaggerContainer className='grid gap-4'>
      <CardStaggerItem className='rounded-xl border border-border bg-card p-5 shadow-sm'>
        <div className='flex flex-wrap items-start justify-between gap-3'>
          <div>
            <p className='text-xs font-medium tracking-[0.14em] text-muted-foreground uppercase'>{t('settings')}</p>
            <h1 className='mt-2 text-2xl font-semibold tracking-tight'>{t('settingsPage.title')}</h1>
            <p className='mt-2 max-w-2xl text-sm leading-6 text-muted-foreground'>{t('settingsPage.description')}</p>
          </div>
          <Button variant='outline' onClick={app.resetAppearance}>
            <RotateCcw className='size-4' />
            {t('reset')}
          </Button>
        </div>
      </CardStaggerItem>

      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-sm font-semibold text-primary-foreground'>
            {initials}
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.accountTitle')}</h2>
              <Badge>{app.auth?.role || 'admin'}</Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>{t('settingsPage.accountDescription')}</p>
            <div className='mt-3 flex items-center gap-2 text-sm'>
              <UserCircle className='size-4 text-muted-foreground' />
              <span className='truncate font-medium'>{username}</span>
            </div>
          </div>
        </div>

        <StaggerContainer className='grid gap-3 sm:grid-cols-2 xl:grid-cols-3'>
          <StaggerItem>
            <InfoTile label={t('profileDialog.userId')} value={app.auth?.id || '-'} />
          </StaggerItem>
          <StaggerItem>
            <InfoTile label={t('profileDialog.sessionExpires')} value={formatDate(app.auth?.expires_at)} />
          </StaggerItem>
          <StaggerItem>
            <InfoTile label={t('servers')} value={String(app.data.servers.length)} />
          </StaggerItem>
          <StaggerItem>
            <InfoTile label={t('credentials')} value={String(app.data.credentials.length)} />
          </StaggerItem>
          <StaggerItem>
            <InfoTile label={t('profileDialog.activeSessions')} value={String(activeSessions)} />
          </StaggerItem>
          <StaggerItem>
            <InfoTile label={t('gateway')} value={app.data.guacd?.address || t('guacdOffline')} />
          </StaggerItem>
        </StaggerContainer>
      </CardStaggerItem>

      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[1.1fr_0.9fr]'>
        <div className='lg:col-span-2'>
          <h2 className='text-base font-semibold'>{t('settingsPage.appearanceTitle')}</h2>
          <p className='mt-1 text-sm leading-6 text-muted-foreground'>{t('settingsPage.appearanceDescription')}</p>
        </div>

        <StaggerContainer className='grid gap-4 sm:grid-cols-2'>
          <StaggerItem>
            <Field label={t('theme')}>
              <Select value={app.theme} onChange={(event) => app.setTheme(event.currentTarget.value as Theme)}>
                <option value='system'>{t('system')}</option>
                <option value='light'>{t('light')}</option>
                <option value='dark'>{t('dark')}</option>
              </Select>
            </Field>
          </StaggerItem>
          <StaggerItem>
            <Field label={t('language')}>
              <Select value={app.locale} onChange={(event) => app.setLocale(event.currentTarget.value as Locale)}>
                {INTERFACE_LANGUAGE_OPTIONS.map((option) => (
                  <option key={option.code} value={option.code}>{option.label}</option>
                ))}
              </Select>
            </Field>
          </StaggerItem>
          <StaggerItem>
            <Field label={t('colorPreset')}>
              <Select value={app.appearance.preset} onChange={(event) => app.setAppearance({ preset: event.currentTarget.value as ThemePreset })}>
                {presetOptions.map((option) => (
                  <option key={option.value} value={option.value}>{t(`preset.${option.value}`, { defaultValue: option.label })}</option>
                ))}
              </Select>
            </Field>
          </StaggerItem>
          <StaggerItem>
            <Field label={t('font')}>
              <Select value={app.appearance.font} onChange={(event) => app.setAppearance({ font: event.currentTarget.value as ThemeFont })}>
                {fontOptions.map((option) => (
                  <option key={option.value} value={option.value}>{t(option.labelKey)}</option>
                ))}
              </Select>
            </Field>
          </StaggerItem>
          <StaggerItem>
            <Field label={t('borderRadius')}>
              <Select value={app.appearance.radius} onChange={(event) => app.setAppearance({ radius: event.currentTarget.value as ThemeRadius })}>
                {radiusOptions.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </Select>
            </Field>
          </StaggerItem>
          <StaggerItem>
            <Field label={t('density')}>
              <Select value={app.appearance.scale} onChange={(event) => app.setAppearance({ scale: event.currentTarget.value as ThemeScale })}>
                {scaleOptions.map((option) => (
                  <option key={option.value} value={option.value}>{t(option.labelKey)}</option>
                ))}
              </Select>
            </Field>
          </StaggerItem>
          <StaggerItem>
            <Field label={t('contentWidth')}>
              <Select value={app.appearance.contentLayout} onChange={(event) => app.setAppearance({ contentLayout: event.currentTarget.value as ThemeContentLayout })}>
                <option value='full'>{t('fullWidth')}</option>
                <option value='centered'>{t('centered')}</option>
              </Select>
            </Field>
          </StaggerItem>
          <StaggerItem>
            <Field label={t('sidebarStyle')}>
              <Select value={app.appearance.sidebarStyle} onChange={(event) => app.setAppearance({ sidebarStyle: event.currentTarget.value as ThemeSidebarStyle })}>
                <option value='default'>{t('default')}</option>
                <option value='inset'>{t('inset')}</option>
                <option value='floating'>{t('floating')}</option>
              </Select>
            </Field>
          </StaggerItem>
        </StaggerContainer>

        <StaggerContainer className='grid content-start gap-3 rounded-xl border border-border bg-muted/25 p-4'>
          <h2 className='text-sm font-semibold'>{t('settingsDialog.systemState')}</h2>
          <div className='grid gap-3'>
            <StaggerItem>
            <PreviewTile icon={app.resolvedTheme === 'dark' ? Moon : app.resolvedTheme === 'light' ? Sun : Monitor} label={t('settingsDialog.resolvedTheme')} value={app.resolvedTheme} />
            </StaggerItem>
            <StaggerItem>
            <InfoTile label={t('settingsDialog.activeLocale')} value={app.locale} />
            </StaggerItem>
            <StaggerItem>
            <InfoTile label={t('gateway')} value={app.data.guacd?.address || t('guacdOffline')} />
            </StaggerItem>
            <StaggerItem>
            <InfoTile label={t('version')} value={app.publicConfig.version || 'dev'} />
            </StaggerItem>
          </div>
        </StaggerContainer>
      </CardStaggerItem>

      <AboutContent />
    </CardStaggerContainer>
  )
}

function PreviewTile({ icon: Icon, label, value }: { icon: typeof Sun; label: string; value: string }) {
  return (
    <div className='flex items-center gap-3 rounded-lg border border-border bg-background/70 p-3'>
      <span className='grid size-9 place-items-center rounded-md bg-primary text-primary-foreground'>
        <Icon className='size-4' />
      </span>
      <div className='min-w-0'>
        <div className='text-xs text-muted-foreground'>{label}</div>
        <div className='mt-0.5 truncate font-mono text-sm'>{value}</div>
      </div>
    </div>
  )
}

function InfoTile({ label, value }: { label: string; value: string }) {
  return (
    <div className='min-w-0 rounded-lg border border-border bg-background/70 p-3'>
      <div className='text-xs text-muted-foreground'>{label}</div>
      <div className='mt-1 truncate font-mono text-sm'>{value}</div>
    </div>
  )
}
