import { Fingerprint, KeyRound, MessageCircle, Monitor, Moon, Network, RotateCcw, ShieldCheck, Sun, Trash2, UserCircle } from 'lucide-react'
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
import {
  decodePasskeyCreationOptions,
  passkeyAttestationPayload,
  passkeySecureContext,
  passkeySupported,
  type PasskeyCreationPublicKeyOptions,
  type PasskeyOptionsResponse,
} from '@/lib/passkeys'
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

interface LDAPSettingsState {
  enabled: boolean
  providerName: string
  url: string
  bindDN: string
  bindPassword: string
  bindPasswordSet: boolean
  baseDN: string
  userFilter: string
  usernameAttribute: string
  displayNameAttribute: string
  emailAttribute: string
  role: string
  autoCreate: boolean
  setting?: PlatformItem
}

interface WeComSettingsState {
  enabled: boolean
  providerName: string
  corpID: string
  agentID: string
  agentSecret: string
  agentSecretSet: boolean
  role: string
  autoCreate: boolean
  setting?: PlatformItem
}

interface PasskeyItem {
  id: string
  name: string
  credential_id: string
  sign_count: number
  last_used_at?: string
  created_at: string
  updated_at: string
}

const loginSecurityTypes = ['security', 'identity', 'login', 'password', 'captcha']
const captchaKeys = ['captcha_enabled', 'login_captcha', 'enable_captcha', 'captcha', 'require_captcha']
const disablePasswordKeys = ['disable_password_login', 'password_login_disabled', 'disablePasswordLogin', 'passwordLoginDisabled', 'no_password_login']
const passwordLoginKeys = ['password_login', 'enable_password_login', 'password_auth', 'local_password_login']
const ldapSettingKeys = ['ldap_enabled', 'ldap_url', 'ldap_base_dn', 'ldap_bind_dn', 'ldap_user_filter', 'ldap_provider_id', 'ldap_provider_name']
const wecomSettingKeys = ['wecom_enabled', 'wecom_corp_id', 'wecom_agent_id', 'wecom_provider_id', 'wecom_provider_name']

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
  const [passkeys, setPasskeys] = useState<PasskeyItem[]>([])
  const [passkeyBusy, setPasskeyBusy] = useState(false)
  const [loginSecurity, setLoginSecurity] = useState<LoginSecurityState>({
    captchaEnabled: app.captchaRequired,
    passwordLoginDisabled: app.passwordLoginDisabled,
  })
  const [loginSecurityBusy, setLoginSecurityBusy] = useState(false)
  const [ldapSettings, setLDAPSettings] = useState<LDAPSettingsState>(() => defaultLDAPSettings())
  const [ldapBusy, setLDAPBusy] = useState(false)
  const [ldapTestUsername, setLDAPTestUsername] = useState('')
  const [ldapTestPassword, setLDAPTestPassword] = useState('')
  const [ldapTestBusy, setLDAPTestBusy] = useState(false)
  const [wecomSettings, setWeComSettings] = useState<WeComSettingsState>(() => defaultWeComSettings())
  const [wecomBusy, setWeComBusy] = useState(false)
  const [wecomTestBusy, setWeComTestBusy] = useState(false)

  const loadMFAStatus = async () => {
    setMFAStatus(await apiRequest<MFAStatus>('/api/auth/mfa/status'))
  }

  const loadPasskeys = async () => {
    const result = await apiRequest<{ items: PasskeyItem[] }>('/api/auth/passkeys')
    setPasskeys(result.items || [])
  }

  const loadLoginSecurity = async () => {
    const result = await apiRequest<{ items: PlatformItem[] }>('/api/admin/system-settings')
    setLoginSecurity(loginSecurityFromSettings(result.items, app.captchaRequired, app.passwordLoginDisabled))
    setLDAPSettings(ldapSettingsFromSettings(result.items))
    setWeComSettings(wecomSettingsFromSettings(result.items))
  }

  useEffect(() => {
    void loadMFAStatus().catch(() => undefined)
    void loadPasskeys().catch(() => undefined)
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

  const registerPasskey = async () => {
    if (!passkeySupported()) {
      app.showToast(t('settingsPage.passkeyUnsupported', { defaultValue: 'This browser does not support passkeys.' }))
      return
    }
    if (!passkeySecureContext()) {
      app.showToast(t('settingsPage.passkeySecureContextRequired', { defaultValue: 'Passkeys require HTTPS or localhost.' }))
      return
    }
    setPasskeyBusy(true)
    try {
      const options = await apiRequest<PasskeyOptionsResponse<PasskeyCreationPublicKeyOptions>>('/api/auth/passkeys/register/options', {
        method: 'POST',
        body: '{}',
      })
      const credential = await navigator.credentials.create({
        publicKey: decodePasskeyCreationOptions(options.publicKey),
      })
      if (!credential) throw new Error(t('operationFailed'))
      await apiRequest<PasskeyItem>('/api/auth/passkeys/register/verify', {
        method: 'POST',
        body: JSON.stringify(passkeyAttestationPayload(credential as PublicKeyCredential, options.challenge_id, `${username} passkey`)),
      })
      await loadPasskeys()
      app.showToast(t('settingsPage.passkeyRegistered', { defaultValue: 'Passkey registered.' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setPasskeyBusy(false)
    }
  }

  const deletePasskey = async (item: PasskeyItem) => {
    if (!window.confirm(t('settingsPage.passkeyDeleteConfirm', { defaultValue: 'Delete this passkey?' }))) return
    setPasskeyBusy(true)
    try {
      await apiRequest(`/api/auth/passkeys/${item.id}`, { method: 'DELETE' })
      await loadPasskeys()
      app.showToast(t('settingsPage.passkeyDeleted', { defaultValue: 'Passkey deleted.' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setPasskeyBusy(false)
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

  const patchLDAP = (next: Partial<LDAPSettingsState>) => setLDAPSettings((current) => ({ ...current, ...next }))
  const patchWeCom = (next: Partial<WeComSettingsState>) => setWeComSettings((current) => ({ ...current, ...next }))

  const saveLDAPSettings = async () => {
    setLDAPBusy(true)
    try {
      const target = ldapSettings.setting
      const metadata: Record<string, unknown> = {
        ...(target?.metadata ?? {}),
        ldap_enabled: ldapSettings.enabled,
        ldap_provider_id: 'default-ldap',
        ldap_provider_name: ldapSettings.providerName.trim() || 'LDAP',
        ldap_url: ldapSettings.url.trim(),
        ldap_bind_dn: ldapSettings.bindDN.trim(),
        ldap_base_dn: ldapSettings.baseDN.trim(),
        ldap_user_filter: ldapSettings.userFilter.trim() || '(uid={username})',
        ldap_username_attribute: ldapSettings.usernameAttribute.trim() || 'uid',
        ldap_display_name_attribute: ldapSettings.displayNameAttribute.trim() || 'cn',
        ldap_email_attribute: ldapSettings.emailAttribute.trim() || 'mail',
        ldap_role: ldapSettings.role || 'user',
        ldap_auto_create: ldapSettings.autoCreate,
      }
      if (ldapSettings.bindPassword.trim()) metadata.ldap_bind_password = ldapSettings.bindPassword.trim()
      const payload = {
        name: target?.name || 'LDAP identity',
        type: 'identity',
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
      patchLDAP({ bindPassword: '' })
      await app.refresh(true)
      await loadLoginSecurity()
      app.showToast(t('saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLDAPBusy(false)
    }
  }

  const testLDAPSettings = async () => {
    setLDAPTestBusy(true)
    try {
      await apiRequest('/api/admin/system-settings/ldap/test', {
        method: 'POST',
        body: JSON.stringify({
          setting_id: ldapSettings.setting?.id,
          username: ldapTestUsername.trim(),
          password: ldapTestPassword,
        }),
      })
      setLDAPTestPassword('')
      app.showToast(t('settingsPage.ldapTestSucceeded', { defaultValue: 'LDAP test login succeeded' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLDAPTestBusy(false)
    }
  }

  const saveWeComSettings = async () => {
    setWeComBusy(true)
    try {
      const target = wecomSettings.setting
      const metadata: Record<string, unknown> = {
        ...(target?.metadata ?? {}),
        wecom_enabled: wecomSettings.enabled,
        wecom_provider_id: 'default-wecom',
        wecom_provider_name: wecomSettings.providerName.trim() || 'Enterprise WeChat',
        wecom_corp_id: wecomSettings.corpID.trim(),
        wecom_agent_id: wecomSettings.agentID.trim(),
        wecom_role: wecomSettings.role || 'user',
        wecom_auto_create: wecomSettings.autoCreate,
      }
      if (wecomSettings.agentSecret.trim()) metadata.wecom_agent_secret = wecomSettings.agentSecret.trim()
      const payload = {
        name: target?.name || 'Enterprise WeChat identity',
        type: 'identity',
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
      patchWeCom({ agentSecret: '' })
      await app.refresh(true)
      await loadLoginSecurity()
      app.showToast(t('saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setWeComBusy(false)
    }
  }

  const testWeComSettings = async () => {
    setWeComTestBusy(true)
    try {
      await apiRequest('/api/admin/system-settings/wecom/test', {
        method: 'POST',
        body: JSON.stringify({ setting_id: wecomSettings.setting?.id }),
      })
      app.showToast(t('settingsPage.wecomTestSucceeded', { defaultValue: 'Enterprise WeChat token test succeeded' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setWeComTestBusy(false)
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
            <Fingerprint className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.passkeyTitle', { defaultValue: 'Passkeys' })}</h2>
              <Badge tone={passkeys.length > 0 ? 'success' : 'warning'}>
                {passkeys.length > 0 ? t('settingsPage.passkeyEnabled', { defaultValue: '{{count}} registered', count: passkeys.length }) : t('settingsPage.passkeyDisabled', { defaultValue: 'Not registered' })}
              </Badge>
              {!passkeySecureContext() ? <Badge tone='danger'>{t('settingsPage.passkeyHttpsRequired', { defaultValue: 'HTTPS required' })}</Badge> : null}
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>
              {t('settingsPage.passkeyDescription', { defaultValue: 'Register browser passkeys for passwordless sign-in. Public keys stay on the server; private keys stay in your authenticator.' })}
            </p>
          </div>
        </div>
        <div className='grid gap-3'>
          {passkeys.length ? (
            <div className='grid gap-2'>
              {passkeys.map((item) => (
                <div key={item.id} className='flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-background/70 p-3'>
                  <div className='min-w-0'>
                    <div className='truncate text-sm font-medium'>{item.name}</div>
                    <div className='mt-1 flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground'>
                      <span>{t('createdAt')}: {formatDate(item.created_at)}</span>
                      <span>{t('settingsPage.passkeyLastUsed', { defaultValue: 'Last used' })}: {item.last_used_at ? formatDate(item.last_used_at) : t('none')}</span>
                      <span>{t('settingsPage.passkeySignCount', { defaultValue: 'Sign count' })}: {item.sign_count || 0}</span>
                    </div>
                  </div>
                  <Button type='button' variant='ghost' size='icon-sm' onClick={() => void deletePasskey(item)} disabled={passkeyBusy} aria-label={t('settingsPage.deletePasskey', { defaultValue: 'Delete passkey' })}>
                    <Trash2 className='size-4' />
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <div className='rounded-lg border border-dashed border-border bg-background/70 p-3 text-sm text-muted-foreground'>
              {t('settingsPage.passkeyEmpty', { defaultValue: 'No passkeys are registered for this account yet.' })}
            </div>
          )}
          <div className='flex justify-end'>
            <Button variant='primary' onClick={() => void registerPasskey()} disabled={passkeyBusy || !passkeySupported() || !passkeySecureContext()}>
              <Fingerprint className='size-4' />
              {passkeyBusy ? t('saving') : t('settingsPage.registerPasskey', { defaultValue: 'Register passkey' })}
            </Button>
          </div>
        </div>
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

      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <Network className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.ldapTitle', { defaultValue: 'LDAP directory login' })}</h2>
              <Badge tone={ldapSettings.enabled ? 'success' : 'warning'}>
                {ldapSettings.enabled ? t('settingsPage.ldapEnabled', { defaultValue: 'LDAP on' }) : t('settingsPage.ldapDisabled', { defaultValue: 'LDAP off' })}
              </Badge>
              <Badge tone={ldapSettings.bindPasswordSet ? 'success' : 'neutral'}>
                {ldapSettings.bindPasswordSet ? t('passwordSaved') : t('passwordNotSet')}
              </Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>
              {t('settingsPage.ldapDescription', { defaultValue: 'Allow users to sign in with an external LDAP directory. Service bind passwords are encrypted server-side and never returned by API responses.' })}
            </p>
          </div>
        </div>
        <div className='grid gap-3'>
          <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
            <input
              type='checkbox'
              className='size-4 accent-primary'
              checked={ldapSettings.enabled}
              onChange={(event) => patchLDAP({ enabled: event.currentTarget.checked })}
            />
            <span>{t('settingsPage.ldapEnableLogin', { defaultValue: 'Enable LDAP login' })}</span>
          </label>
          <div className='grid gap-3 md:grid-cols-2'>
            <Field label={t('name')}>
              <Input value={ldapSettings.providerName} onChange={(event) => patchLDAP({ providerName: event.currentTarget.value })} placeholder='Corporate LDAP' />
            </Field>
            <Field label={t('settingsPage.ldapUrl', { defaultValue: 'LDAP URL' })}>
              <Input value={ldapSettings.url} onChange={(event) => patchLDAP({ url: event.currentTarget.value })} placeholder='ldap://directory.example.com:389' />
            </Field>
            <Field label={t('settingsPage.ldapBindDN', { defaultValue: 'Bind DN' })}>
              <Input value={ldapSettings.bindDN} onChange={(event) => patchLDAP({ bindDN: event.currentTarget.value })} placeholder='cn=reader,dc=example,dc=com' />
            </Field>
            <Field label={t('password')}>
              <Input type='password' value={ldapSettings.bindPassword} onChange={(event) => patchLDAP({ bindPassword: event.currentTarget.value })} placeholder={ldapSettings.bindPasswordSet ? 'Leave blank to keep current password' : ''} autoComplete='new-password' />
            </Field>
            <Field label={t('settingsPage.ldapBaseDN', { defaultValue: 'Base DN' })}>
              <Input value={ldapSettings.baseDN} onChange={(event) => patchLDAP({ baseDN: event.currentTarget.value })} placeholder='ou=people,dc=example,dc=com' />
            </Field>
            <Field label={t('settingsPage.ldapUserFilter', { defaultValue: 'User filter' })}>
              <Input value={ldapSettings.userFilter} onChange={(event) => patchLDAP({ userFilter: event.currentTarget.value })} placeholder='(uid={username})' />
            </Field>
            <Field label={t('settingsPage.ldapUsernameAttribute', { defaultValue: 'Username attribute' })}>
              <Input value={ldapSettings.usernameAttribute} onChange={(event) => patchLDAP({ usernameAttribute: event.currentTarget.value })} placeholder='uid' />
            </Field>
            <Field label={t('settingsPage.ldapDisplayNameAttribute', { defaultValue: 'Display name attribute' })}>
              <Input value={ldapSettings.displayNameAttribute} onChange={(event) => patchLDAP({ displayNameAttribute: event.currentTarget.value })} placeholder='cn' />
            </Field>
            <Field label={t('settingsPage.ldapEmailAttribute', { defaultValue: 'Email attribute' })}>
              <Input value={ldapSettings.emailAttribute} onChange={(event) => patchLDAP({ emailAttribute: event.currentTarget.value })} placeholder='mail' />
            </Field>
            <Field label={t('settingsPage.defaultRole', { defaultValue: 'Default role' })}>
              <Select value={ldapSettings.role} onChange={(event) => patchLDAP({ role: event.currentTarget.value })}>
                <option value='user'>user</option>
                <option value='auditor'>auditor</option>
                <option value='admin'>admin</option>
              </Select>
            </Field>
          </div>
          <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
            <input
              type='checkbox'
              className='size-4 accent-primary'
              checked={ldapSettings.autoCreate}
              onChange={(event) => patchLDAP({ autoCreate: event.currentTarget.checked })}
            />
            <span>{t('settingsPage.ldapAutoCreate', { defaultValue: 'Create LDAP users on first successful login' })}</span>
          </label>
          <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div>
              <div className='text-sm font-medium'>{t('settingsPage.ldapTestTitle', { defaultValue: 'Test LDAP login' })}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.ldapTestDescription', { defaultValue: 'Validate the saved LDAP provider with a directory username and password. Test credentials are never stored.' })}</p>
            </div>
            <div className='grid gap-3 md:grid-cols-2'>
              <Field label={t('settingsPage.ldapTestUsername', { defaultValue: 'Test username' })}>
                <Input value={ldapTestUsername} onChange={(event) => setLDAPTestUsername(event.currentTarget.value)} autoComplete='username' />
              </Field>
              <Field label={t('settingsPage.ldapTestPassword', { defaultValue: 'Test password' })}>
                <Input type='password' value={ldapTestPassword} onChange={(event) => setLDAPTestPassword(event.currentTarget.value)} autoComplete='current-password' />
              </Field>
            </div>
            <div className='flex justify-end'>
              <Button
                variant='outline'
                onClick={() => void testLDAPSettings()}
                disabled={ldapTestBusy || !ldapSettings.setting?.id || !ldapTestUsername.trim() || !ldapTestPassword}
              >
                {ldapTestBusy ? t('testing') : t('settingsPage.testLDAP', { defaultValue: 'Test LDAP' })}
              </Button>
            </div>
          </div>
          <div className='flex justify-end'>
            <Button variant='primary' onClick={() => void saveLDAPSettings()} disabled={ldapBusy || (ldapSettings.enabled && (!ldapSettings.url.trim() || !ldapSettings.baseDN.trim()))}>
              {ldapBusy ? t('saving') : t('save')}
            </Button>
          </div>
        </div>
      </CardStaggerItem>

      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <MessageCircle className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.wecomTitle', { defaultValue: 'Enterprise WeChat login' })}</h2>
              <Badge tone={wecomSettings.enabled ? 'success' : 'warning'}>
                {wecomSettings.enabled ? t('settingsPage.wecomEnabled', { defaultValue: 'WeCom on' }) : t('settingsPage.wecomDisabled', { defaultValue: 'WeCom off' })}
              </Badge>
              <Badge tone={wecomSettings.agentSecretSet ? 'success' : 'neutral'}>
                {wecomSettings.agentSecretSet ? t('passwordSaved') : t('passwordNotSet')}
              </Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>
              {t('settingsPage.wecomDescription', { defaultValue: 'Allow users to sign in through Enterprise WeChat OAuth. Agent secrets are encrypted server-side and never returned by API responses.' })}
            </p>
          </div>
        </div>
        <div className='grid gap-3'>
          <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
            <input
              type='checkbox'
              className='size-4 accent-primary'
              checked={wecomSettings.enabled}
              onChange={(event) => patchWeCom({ enabled: event.currentTarget.checked })}
            />
            <span>{t('settingsPage.wecomEnableLogin', { defaultValue: 'Enable Enterprise WeChat login' })}</span>
          </label>
          <div className='grid gap-3 md:grid-cols-2'>
            <Field label={t('name')}>
              <Input value={wecomSettings.providerName} onChange={(event) => patchWeCom({ providerName: event.currentTarget.value })} placeholder='Enterprise WeChat' />
            </Field>
            <Field label={t('settingsPage.wecomCorpID', { defaultValue: 'Corp ID' })}>
              <Input value={wecomSettings.corpID} onChange={(event) => patchWeCom({ corpID: event.currentTarget.value })} placeholder='wwxxxxxxxxxxxxxxxx' />
            </Field>
            <Field label={t('settingsPage.wecomAgentID', { defaultValue: 'Agent ID' })}>
              <Input value={wecomSettings.agentID} onChange={(event) => patchWeCom({ agentID: event.currentTarget.value })} placeholder='1000002' />
            </Field>
            <Field label={t('settingsPage.wecomAgentSecret', { defaultValue: 'Agent secret' })}>
              <Input type='password' value={wecomSettings.agentSecret} onChange={(event) => patchWeCom({ agentSecret: event.currentTarget.value })} placeholder={wecomSettings.agentSecretSet ? 'Leave blank to keep current secret' : ''} autoComplete='new-password' />
            </Field>
            <Field label={t('settingsPage.defaultRole', { defaultValue: 'Default role' })}>
              <Select value={wecomSettings.role} onChange={(event) => patchWeCom({ role: event.currentTarget.value })}>
                <option value='user'>user</option>
                <option value='auditor'>auditor</option>
                <option value='admin'>admin</option>
              </Select>
            </Field>
          </div>
          <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
            <input
              type='checkbox'
              className='size-4 accent-primary'
              checked={wecomSettings.autoCreate}
              onChange={(event) => patchWeCom({ autoCreate: event.currentTarget.checked })}
            />
            <span>{t('settingsPage.wecomAutoCreate', { defaultValue: 'Create Enterprise WeChat users on first successful login' })}</span>
          </label>
          <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div>
              <div className='text-sm font-medium'>{t('settingsPage.wecomTestTitle', { defaultValue: 'Test Enterprise WeChat token' })}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.wecomTestDescription', { defaultValue: 'Validate the saved Corp ID and agent secret by requesting a WeCom access token. Tokens and secrets are never shown.' })}</p>
            </div>
            <div className='flex justify-end'>
              <Button
                variant='outline'
                onClick={() => void testWeComSettings()}
                disabled={wecomTestBusy || !wecomSettings.setting?.id}
              >
                {wecomTestBusy ? t('testing') : t('settingsPage.testWeCom', { defaultValue: 'Test WeCom' })}
              </Button>
            </div>
          </div>
          <div className='flex justify-end'>
            <Button variant='primary' onClick={() => void saveWeComSettings()} disabled={wecomBusy || (wecomSettings.enabled && (!wecomSettings.corpID.trim() || !wecomSettings.agentSecret.trim() && !wecomSettings.agentSecretSet))}>
              {wecomBusy ? t('saving') : t('save')}
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

function defaultLDAPSettings(): LDAPSettingsState {
  return {
    enabled: false,
    providerName: 'LDAP',
    url: '',
    bindDN: '',
    bindPassword: '',
    bindPasswordSet: false,
    baseDN: '',
    userFilter: '(uid={username})',
    usernameAttribute: 'uid',
    displayNameAttribute: 'cn',
    emailAttribute: 'mail',
    role: 'user',
    autoCreate: true,
  }
}

function defaultWeComSettings(): WeComSettingsState {
  return {
    enabled: false,
    providerName: 'Enterprise WeChat',
    corpID: '',
    agentID: '',
    agentSecret: '',
    agentSecretSet: false,
    role: 'user',
    autoCreate: true,
  }
}

function ldapSettingsFromSettings(items: PlatformItem[]): LDAPSettingsState {
  const candidates = items.filter((item) => {
    const type = (item.type || '').trim().toLowerCase()
    return platformItemEnabled(item) && type === 'identity' && hasLDAPMetadata(item)
  })
  const setting = candidates.find((item) => item.name === 'LDAP identity') || candidates[0]
  if (!setting) return defaultLDAPSettings()
  const metadata = setting.metadata ?? {}
  return {
    enabled: metadataBoolValue(metadata.ldap_enabled) === true || metadataBoolValue(metadata.ldap_login_enabled) === true,
    providerName: metadataText(metadata.ldap_provider_name) || metadataText(metadata.provider_name) || setting.name || 'LDAP',
    url: metadataText(metadata.ldap_url) || metadataText(metadata.url) || '',
    bindDN: metadataText(metadata.ldap_bind_dn) || metadataText(metadata.bind_dn) || '',
    bindPassword: '',
    bindPasswordSet: metadataBoolValue(metadata.ldap_bind_password_set) === true,
    baseDN: metadataText(metadata.ldap_base_dn) || metadataText(metadata.base_dn) || '',
    userFilter: metadataText(metadata.ldap_user_filter) || metadataText(metadata.user_filter) || '(uid={username})',
    usernameAttribute: metadataText(metadata.ldap_username_attribute) || metadataText(metadata.username_attribute) || 'uid',
    displayNameAttribute: metadataText(metadata.ldap_display_name_attribute) || metadataText(metadata.display_name_attribute) || 'cn',
    emailAttribute: metadataText(metadata.ldap_email_attribute) || metadataText(metadata.email_attribute) || 'mail',
    role: metadataText(metadata.ldap_role) || metadataText(metadata.role) || 'user',
    autoCreate: metadata.ldap_auto_create === undefined ? true : metadataBoolValue(metadata.ldap_auto_create) === true,
    setting,
  }
}

function wecomSettingsFromSettings(items: PlatformItem[]): WeComSettingsState {
  const candidates = items.filter((item) => {
    const type = (item.type || '').trim().toLowerCase()
    return platformItemEnabled(item) && type === 'identity' && hasWeComMetadata(item)
  })
  const setting = candidates.find((item) => item.name === 'Enterprise WeChat identity') || candidates[0]
  if (!setting) return defaultWeComSettings()
  const metadata = setting.metadata ?? {}
  return {
    enabled: metadataBoolValue(metadata.wecom_enabled) === true || metadataBoolValue(metadata.wecom_login_enabled) === true || metadataBoolValue(metadata.enterprise_wechat_enabled) === true,
    providerName: metadataText(metadata.wecom_provider_name) || metadataText(metadata.enterprise_wechat_provider_name) || metadataText(metadata.provider_name) || setting.name || 'Enterprise WeChat',
    corpID: metadataText(metadata.wecom_corp_id) || metadataText(metadata.enterprise_wechat_corp_id) || metadataText(metadata.corp_id) || '',
    agentID: metadataText(metadata.wecom_agent_id) || metadataText(metadata.enterprise_wechat_agent_id) || metadataText(metadata.agent_id) || '',
    agentSecret: '',
    agentSecretSet: metadataBoolValue(metadata.wecom_agent_secret_set) === true,
    role: metadataText(metadata.wecom_role) || metadataText(metadata.role) || 'user',
    autoCreate: metadata.wecom_auto_create === undefined ? true : metadataBoolValue(metadata.wecom_auto_create) === true,
    setting,
  }
}

function hasLDAPMetadata(item: PlatformItem) {
  const metadata = item.metadata ?? {}
  return ldapSettingKeys.some((key) => Object.prototype.hasOwnProperty.call(metadata, key))
}

function hasWeComMetadata(item: PlatformItem) {
  const metadata = item.metadata ?? {}
  return wecomSettingKeys.some((key) => Object.prototype.hasOwnProperty.call(metadata, key))
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

function metadataText(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return ''
}
