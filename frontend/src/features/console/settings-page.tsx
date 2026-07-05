import { KeyRound, Monitor, Moon, RotateCcw, ShieldCheck, Sun, UserCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { CardStaggerContainer, CardStaggerItem, StaggerContainer, StaggerItem } from '@/components/page-transition'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Field, Input, Select } from '@/components/ui/field'
import { AboutContent } from '@/features/about/about-page'
import { INTERFACE_LANGUAGE_OPTIONS } from '@/i18n/languages'
import { apiRequest } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import type { Locale, PlatformItem, Theme, ThemeContentLayout, ThemeFont, ThemePreset, ThemeRadius, ThemeScale, ThemeSidebarStyle } from '@/types'

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

interface MFAStatus {
  enabled: boolean
  forced: boolean
  recovery_count: number
}

interface MFASetup {
  secret: string
  otpauth_url: string
}

interface LoginSecurityState {
  captchaEnabled: boolean
  passwordLoginDisabled: boolean
  setting?: PlatformItem
}

const loginSecurityTypes = ['security', 'identity', 'login', 'password', 'captcha']
const captchaKeys = ['captcha_enabled', 'login_captcha', 'enable_captcha', 'captcha', 'require_captcha']
const disablePasswordKeys = ['disable_password_login', 'password_login_disabled', 'disablePasswordLogin', 'passwordLoginDisabled', 'no_password_login']
const passwordLoginKeys = ['password_login', 'enable_password_login', 'password_auth', 'local_password_login']

export function SettingsPage() {
  const app = useApp()
  const { t } = useTranslation()
  const activeSessions = app.data.sessions.filter((session) => session.status === 'active').length
  const username = app.auth?.username || 'admin'
  const initials = username.slice(0, 2).toUpperCase()
  const [mfaStatus, setMFAStatus] = useState<MFAStatus | null>(null)
  const [mfaSetup, setMFASetup] = useState<MFASetup | null>(null)
  const [mfaCode, setMFACode] = useState('')
  const [mfaPassword, setMFAPassword] = useState('')
  const [mfaBusy, setMFABusy] = useState(false)
  const [loginSecurity, setLoginSecurity] = useState<LoginSecurityState>({
    captchaEnabled: app.captchaRequired,
    passwordLoginDisabled: app.passwordLoginDisabled,
  })
  const [loginSecurityBusy, setLoginSecurityBusy] = useState(false)

  const loadMFAStatus = async () => {
    setMFAStatus(await apiRequest<MFAStatus>('/api/auth/mfa/status'))
  }

  const loadLoginSecurity = async () => {
    const result = await apiRequest<{ items: PlatformItem[] }>('/api/admin/system-settings')
    setLoginSecurity(loginSecurityFromSettings(result.items, app.captchaRequired, app.passwordLoginDisabled))
  }

  useEffect(() => {
    void loadMFAStatus().catch(() => undefined)
    void loadLoginSecurity().catch(() => undefined)
  }, [])

  useEffect(() => {
    setLoginSecurity((current) => ({
      ...current,
      captchaEnabled: app.captchaRequired,
      passwordLoginDisabled: app.passwordLoginDisabled,
    }))
  }, [app.captchaRequired, app.passwordLoginDisabled])

  const startMFASetup = async () => {
    setMFABusy(true)
    try {
      setMFASetup(await apiRequest<MFASetup>('/api/auth/mfa/setup', { method: 'POST', body: '{}' }))
      setMFACode('')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setMFABusy(false)
    }
  }

  const enableMFA = async () => {
    if (!mfaSetup) return
    setMFABusy(true)
    try {
      const result = await apiRequest<{ recovery_codes: string[] }>('/api/auth/mfa/enable', {
        method: 'POST',
        body: JSON.stringify({ secret: mfaSetup.secret, mfa_code: mfaCode }),
      })
      setMFASetup(null)
      setMFACode('')
      await loadMFAStatus()
      if (result.recovery_codes?.length) window.alert(`Recovery codes:\n\n${result.recovery_codes.join('\n')}`)
      app.showToast('MFA enabled')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setMFABusy(false)
    }
  }

  const disableMFA = async () => {
    setMFABusy(true)
    try {
      await apiRequest('/api/auth/mfa/disable', {
        method: 'POST',
        body: JSON.stringify({ current_password: mfaPassword, mfa_code: mfaCode }),
      })
      setMFASetup(null)
      setMFACode('')
      setMFAPassword('')
      await loadMFAStatus()
      app.showToast('MFA disabled')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setMFABusy(false)
    }
  }

  const updateLoginSecurity = async (next: Partial<LoginSecurityState>) => {
    setLoginSecurityBusy(true)
    try {
      const merged = { ...loginSecurity, ...next }
      const result = await apiRequest<{ items: PlatformItem[] }>('/api/admin/system-settings')
      const current = loginSecurityFromSettings(result.items, app.captchaRequired, app.passwordLoginDisabled)
      const target = current.setting
      const metadata = {
        ...(target?.metadata ?? {}),
        captcha_enabled: merged.captchaEnabled,
        disable_password_login: merged.passwordLoginDisabled,
        password_login: !merged.passwordLoginDisabled,
      }
      const payload = {
        name: target?.name || 'Login security',
        type: target?.type && target.type !== 'captcha' ? target.type : 'security',
        status: 'enabled',
        metadata,
      }
      if (target?.id) {
        await apiRequest<PlatformItem>(`/api/admin/system-settings/${target.id}`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        })
      } else {
        await apiRequest<PlatformItem>('/api/admin/system-settings', {
          method: 'POST',
          body: JSON.stringify(payload),
        })
      }
      await app.refresh(true)
      await loadLoginSecurity()
      app.showToast(t('saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoginSecurityBusy(false)
    }
  }

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

      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <ShieldCheck className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>Multi-factor authentication</h2>
              <Badge tone={mfaStatus?.enabled ? 'success' : 'warning'}>{mfaStatus?.enabled ? 'enabled' : 'disabled'}</Badge>
              {mfaStatus?.forced ? <Badge tone='danger'>required</Badge> : null}
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>Use TOTP codes from an authenticator app before a browser session cookie is issued.</p>
            <p className='mt-2 text-xs text-muted-foreground'>Recovery codes remaining: {mfaStatus?.recovery_count ?? 0}</p>
          </div>
        </div>
        <div className='grid gap-3'>
          {mfaSetup ? (
            <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
              <Field label='TOTP secret'>
                <Input readOnly className='font-mono text-xs' value={mfaSetup.secret} />
              </Field>
              <Field label='otpauth URL'>
                <Input readOnly className='font-mono text-xs' value={mfaSetup.otpauth_url} />
              </Field>
              <Field label='Current MFA code'>
                <Input value={mfaCode} onChange={(event) => setMFACode(event.currentTarget.value)} inputMode='numeric' placeholder='123456' />
              </Field>
              <div className='flex flex-wrap justify-end gap-2'>
                <Button variant='outline' onClick={() => setMFASetup(null)} disabled={mfaBusy}>{t('cancel')}</Button>
                <Button variant='primary' onClick={() => void enableMFA()} disabled={mfaBusy || !mfaCode.trim()}>Enable MFA</Button>
              </div>
            </div>
          ) : mfaStatus?.enabled ? (
            <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
              <Field label='Current password'>
                <Input type='password' value={mfaPassword} onChange={(event) => setMFAPassword(event.currentTarget.value)} />
              </Field>
              <Field label='Current MFA code'>
                <Input value={mfaCode} onChange={(event) => setMFACode(event.currentTarget.value)} inputMode='numeric' placeholder='123456' />
              </Field>
              <div className='flex justify-end'>
                <Button variant='destructive' onClick={() => void disableMFA()} disabled={mfaBusy || !mfaPassword.trim() || !mfaCode.trim()}>Disable MFA</Button>
              </div>
            </div>
          ) : (
            <div className='flex justify-end'>
              <Button variant='primary' onClick={() => void startMFASetup()} disabled={mfaBusy}>Set up MFA</Button>
            </div>
          )}
        </div>
      </CardStaggerItem>

      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <KeyRound className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.loginSecurityTitle')}</h2>
              <Badge tone={loginSecurity.captchaEnabled ? 'success' : 'warning'}>
                {loginSecurity.captchaEnabled ? t('settingsPage.captchaEnabled') : t('settingsPage.captchaDisabled')}
              </Badge>
              <Badge tone={loginSecurity.passwordLoginDisabled ? 'danger' : 'success'}>
                {loginSecurity.passwordLoginDisabled ? t('settingsPage.passwordLoginDisabled') : t('settingsPage.passwordLoginEnabled')}
              </Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>{t('settingsPage.loginSecurityDescription')}</p>
            {loginSecurity.passwordLoginDisabled ? (
              <p className='mt-2 text-xs leading-5 text-amber-600 dark:text-amber-300'>{t('settingsPage.passwordLoginDisabledWarning')}</p>
            ) : null}
          </div>
        </div>
        <div className='grid gap-3'>
          <div className='flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div className='min-w-0'>
              <div className='text-sm font-medium'>{t('settingsPage.loginCaptchaTitle')}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.loginCaptchaDescription')}</p>
            </div>
            <Button
              variant={loginSecurity.captchaEnabled ? 'outline' : 'primary'}
              onClick={() => void updateLoginSecurity({ captchaEnabled: !loginSecurity.captchaEnabled })}
              disabled={loginSecurityBusy}
            >
              {loginSecurity.captchaEnabled ? t('settingsPage.disableCaptcha') : t('settingsPage.enableCaptcha')}
            </Button>
          </div>
          <div className='flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div className='min-w-0'>
              <div className='text-sm font-medium'>{t('settingsPage.passwordLoginTitle')}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.passwordLoginDescription')}</p>
            </div>
            <Button
              variant={loginSecurity.passwordLoginDisabled ? 'primary' : 'destructive'}
              onClick={() => void updateLoginSecurity({ passwordLoginDisabled: !loginSecurity.passwordLoginDisabled })}
              disabled={loginSecurityBusy}
            >
              {loginSecurity.passwordLoginDisabled ? t('settingsPage.enablePasswordLogin') : t('settingsPage.disablePasswordLogin')}
            </Button>
          </div>
        </div>
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

function loginSecurityFromSettings(items: PlatformItem[], fallbackCaptcha: boolean, fallbackPasswordDisabled: boolean): LoginSecurityState {
  let captchaEnabled = fallbackCaptcha
  let passwordLoginDisabled = fallbackPasswordDisabled
  const candidates = items.filter((item) => platformItemEnabled(item) && loginSecurityTypes.includes((item.type || '').trim().toLowerCase()))
  for (const item of candidates) {
    const metadata = item.metadata ?? {}
    if (captchaKeys.some((key) => metadataTruthy(metadata[key]))) {
      captchaEnabled = true
    }
    if (disablePasswordKeys.some((key) => metadataTruthy(metadata[key]))) {
      passwordLoginDisabled = true
    }
    for (const key of passwordLoginKeys) {
      const parsed = metadataBoolValue(metadata[key])
      if (parsed !== null && !parsed) {
        passwordLoginDisabled = true
      }
    }
  }
  const setting =
    candidates.find((item) => item.name === 'Login security') ||
    candidates.find((item) => hasLoginSecurityMetadata(item)) ||
    candidates[0]
  return { captchaEnabled, passwordLoginDisabled, setting }
}

function hasLoginSecurityMetadata(item: PlatformItem) {
  const metadata = item.metadata ?? {}
  return [...captchaKeys, ...disablePasswordKeys, ...passwordLoginKeys].some((key) => Object.prototype.hasOwnProperty.call(metadata, key))
}

function platformItemEnabled(item: PlatformItem) {
  const status = (item.status || '').trim().toLowerCase()
  return status === '' || status === 'enabled' || status === 'active' || status === 'locked'
}

function metadataTruthy(value: unknown) {
  return metadataBoolValue(value) === true
}

function metadataBoolValue(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  if (typeof value !== 'string') return null
  const normalized = value.trim().toLowerCase()
  if (['true', '1', 'yes', 'enabled', 'required', 'on'].includes(normalized)) return true
  if (['false', '0', 'no', 'disabled', 'off'].includes(normalized)) return false
  return null
}
