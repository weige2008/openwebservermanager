import { BadgeCheck, Fingerprint, Globe2, History, KeyRound, MessageCircle, Monitor, Moon, Network, RotateCcw, ShieldCheck, Sun, Trash2, UserCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { CardStaggerContainer, CardStaggerItem, StaggerContainer, StaggerItem } from '@/components/page-transition'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useConfirmDialog } from '@/components/ui/confirm-dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
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
import { canUseAPI } from '@/lib/rbac'
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

const maxPasskeysPerUser = 20

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
  forceMFARequired: boolean
  loginFailureThreshold: number
  loginFailureWindowMinutes: number
  loginLockMinutes: number
  setting?: PlatformItem
}

interface LoginPolicyFormState {
  name: string
  action: 'allow' | 'deny'
  account: string
  cidr: string
  priority: number
  expiresAt: string
}

interface OIDCSettingsState {
  enabled: boolean
  providerName: string
  issuer: string
  authorizationEndpoint: string
  tokenEndpoint: string
  userInfoEndpoint: string
  jwksEndpoint: string
  clientID: string
  clientSecret: string
  clientSecretSet: boolean
  clientSecretClear: boolean
  tokenAuthMethod: 'client_secret_basic' | 'client_secret_post' | 'none'
  requireIDToken: boolean
  scopes: string
  role: string
  autoCreate: boolean
  setting?: PlatformItem
}

interface LDAPSettingsState {
  enabled: boolean
  providerName: string
  url: string
  bindDN: string
  bindPassword: string
  bindPasswordSet: boolean
  bindPasswordClear: boolean
  baseDN: string
  userFilter: string
  userDNTemplate: string
  usernameAttribute: string
  displayNameAttribute: string
  emailAttribute: string
  role: string
  autoCreate: boolean
  startTLS: boolean
  serverName: string
  insecureSkipVerify: boolean
  setting?: PlatformItem
}

interface WeComSettingsState {
  enabled: boolean
  providerName: string
  corpID: string
  agentID: string
  agentSecret: string
  agentSecretSet: boolean
  agentSecretClear: boolean
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

interface SSHPublicKeyItem {
  id: string
  name: string
  type: string
  status: string
  public_key: string
  fingerprint: string
  comment?: string
  created_at: string
}

interface LocalLicenseModule {
  key: string
  name: string
  enabled: boolean
}

interface LocalLicenseInfo {
  edition: string
  status: string
  enforcement: string
  licensee?: string
  contact?: string
  serial?: string
  issued_at?: string
  expires_at?: string
  notes?: string
  updated_at?: string
  setting_id?: string
  version: string
  commit?: string
  installation_fingerprint: string
  runtime: Record<string, string>
  limits: Record<string, string>
  usage: Record<string, number>
  features?: string[]
  modules: LocalLicenseModule[]
}

interface LocalLicenseFormState {
  licensee: string
  contact: string
  serial: string
  issued_at: string
  expires_at: string
  notes: string
  features: string
}

interface RetentionSettingsState {
  sessionDays: number
  loginDays: number
  scheduledTaskDays: number
  operationDays: number
  fileDays: number
  accessDays: number
  sqlDays: number
  execCommandDays: number
  setting?: PlatformItem
}

type RetentionNumberKey = Exclude<keyof RetentionSettingsState, 'setting'>

const retentionFieldOptions: Array<{ key: RetentionNumberKey; labelKey: string; descriptionKey: string }> = [
  { key: 'sessionDays', labelKey: 'settingsPage.retentionSessions', descriptionKey: 'settingsPage.retentionSessionsDescription' },
  { key: 'loginDays', labelKey: 'settingsPage.retentionLoginLogs', descriptionKey: 'settingsPage.retentionLoginLogsDescription' },
  { key: 'scheduledTaskDays', labelKey: 'settingsPage.retentionScheduledTaskLogs', descriptionKey: 'settingsPage.retentionScheduledTaskLogsDescription' },
  { key: 'operationDays', labelKey: 'settingsPage.retentionOperationLogs', descriptionKey: 'settingsPage.retentionOperationLogsDescription' },
  { key: 'fileDays', labelKey: 'settingsPage.retentionFileLogs', descriptionKey: 'settingsPage.retentionFileLogsDescription' },
  { key: 'accessDays', labelKey: 'settingsPage.retentionAccessLogs', descriptionKey: 'settingsPage.retentionAccessLogsDescription' },
  { key: 'sqlDays', labelKey: 'settingsPage.retentionSQLLogs', descriptionKey: 'settingsPage.retentionSQLLogsDescription' },
  { key: 'execCommandDays', labelKey: 'settingsPage.retentionExecCommandLogs', descriptionKey: 'settingsPage.retentionExecCommandLogsDescription' },
]

const loginSecurityTypes = ['security', 'identity', 'login', 'password', 'captcha', 'mfa']
const captchaKeys = ['captcha_enabled', 'login_captcha', 'enable_captcha', 'captcha', 'require_captcha']
const disablePasswordKeys = ['disable_password_login', 'password_login_disabled', 'disablePasswordLogin', 'passwordLoginDisabled', 'no_password_login']
const passwordLoginKeys = ['password_login', 'enable_password_login', 'password_auth', 'local_password_login']
const forceMFAKeys = ['force_mfa', 'forceMFA', 'mfa_required', 'require_mfa']
const loginFailureThresholdKeys = ['login_failure_threshold', 'failure_threshold', 'max_login_failures', 'login_lock_threshold', 'lock_threshold']
const loginFailureWindowKeys = ['login_failure_window_minutes', 'failure_window_minutes', 'login_lock_window_minutes', 'lock_window_minutes']
const loginLockMinutesKeys = ['login_lock_minutes', 'lock_minutes', 'login_lock_duration_minutes', 'lock_duration_minutes']
const defaultLoginPolicyForm: LoginPolicyFormState = { name: '', action: 'deny', account: '*', cidr: '', priority: 0, expiresAt: '' }
const oidcSettingKeys = ['oidc_login_enabled', 'external_oidc_enabled', 'oidc_issuer', 'oidc_jwks_uri', 'oidc_authorization_endpoint', 'oidc_token_endpoint', 'oidc_client_id', 'oidc_provider_id']
const ldapSettingKeys = ['ldap_enabled', 'ldap_url', 'ldap_base_dn', 'ldap_bind_dn', 'ldap_user_filter', 'ldap_user_dn_template', 'ldap_start_tls', 'ldap_server_name', 'ldap_provider_id', 'ldap_provider_name']
const wecomSettingKeys = ['wecom_enabled', 'wecom_corp_id', 'wecom_agent_id', 'wecom_provider_id', 'wecom_provider_name']

export function SettingsPage() {
  const app = useApp()
  const { t } = useTranslation()
  const { confirm, confirmDialog } = useConfirmDialog()
  const activeSessions = app.data.sessions.filter((session) => session.status === 'active').length
  const username = app.auth?.username || 'admin'
  const initials = username.slice(0, 2).toUpperCase()
  const role = app.auth?.role
  const apiPermissions = app.auth?.api_permissions || []
  const canUsePath = (method: string, path: string) => canUseAPI(role, apiPermissions, method, path)
  const canReadSystemSettings = canUsePath('GET', '/api/admin/system-settings')
  const canCreateSystemSettings = canUsePath('POST', '/api/admin/system-settings')
  const canSaveSystemSetting = (id?: string) => id ? canUsePath('PATCH', `/api/admin/system-settings/${id}`) : canCreateSystemSettings
  const canTestOIDCSettings = canUsePath('POST', '/api/admin/system-settings/oidc/test')
  const canTestLDAPSettings = canUsePath('POST', '/api/admin/system-settings/ldap/test')
  const canTestWeComSettings = canUsePath('POST', '/api/admin/system-settings/wecom/test')
  const canReadLoginPolicies = canUsePath('GET', '/api/admin/login-policies')
  const canCreateLoginPolicy = canUsePath('POST', '/api/admin/login-policies')
  const canPatchLoginPolicy = (id: string) => canUsePath('PATCH', `/api/admin/login-policies/${id}`)
  const canDeleteLoginPolicy = (id: string) => canUsePath('DELETE', `/api/admin/login-policies/${id}`)
  const canReadLoginLocks = canUsePath('GET', '/api/admin/login-locked')
  const canDeleteLoginLock = (id: string) => canUsePath('DELETE', `/api/admin/login-locked/${id}`)
  const canReadLicense = canUsePath('GET', '/api/admin/license')
  const canSaveLicense = canUsePath('PUT', '/api/admin/license')
  const [mfaStatus, setMFAStatus] = useState<MFAStatus | null>(null)
  const [mfaSetup, setMFASetup] = useState<MFASetup | null>(null)
  const [mfaCode, setMFACode] = useState('')
  const [mfaPassword, setMFAPassword] = useState('')
  const [mfaRecoveryCodes, setMFARecoveryCodes] = useState<string[]>([])
  const [mfaBusy, setMFABusy] = useState(false)
  const [passkeys, setPasskeys] = useState<PasskeyItem[]>([])
  const [passkeyName, setPasskeyName] = useState('')
  const [passkeyBusy, setPasskeyBusy] = useState(false)
  const [sshPublicKeys, setSSHPublicKeys] = useState<SSHPublicKeyItem[]>([])
  const [sshPublicKeyForm, setSSHPublicKeyForm] = useState({ name: '', publicKey: '' })
  const [sshPublicKeyBusy, setSSHPublicKeyBusy] = useState(false)
  const [loginSecurity, setLoginSecurity] = useState<LoginSecurityState>({
    captchaEnabled: app.captchaRequired,
    passwordLoginDisabled: app.passwordLoginDisabled,
    forceMFARequired: false,
    loginFailureThreshold: 5,
    loginFailureWindowMinutes: 15,
    loginLockMinutes: 5,
  })
  const [loginSecurityBusy, setLoginSecurityBusy] = useState(false)
  const [retentionSettings, setRetentionSettings] = useState<RetentionSettingsState>(() => defaultRetentionSettings())
  const [retentionBusy, setRetentionBusy] = useState(false)
  const [loginPolicies, setLoginPolicies] = useState<PlatformItem[]>([])
  const [loginPolicyForm, setLoginPolicyForm] = useState<LoginPolicyFormState>(defaultLoginPolicyForm)
  const [loginPolicyBusy, setLoginPolicyBusy] = useState(false)
  const [loginLocks, setLoginLocks] = useState<PlatformItem[]>([])
  const [loginLockBusy, setLoginLockBusy] = useState(false)
  const [oidcSettings, setOIDCSettings] = useState<OIDCSettingsState>(() => defaultOIDCSettings())
  const [oidcBusy, setOIDCBusy] = useState(false)
  const [oidcTestBusy, setOIDCTestBusy] = useState(false)
  const [ldapSettings, setLDAPSettings] = useState<LDAPSettingsState>(() => defaultLDAPSettings())
  const [ldapBusy, setLDAPBusy] = useState(false)
  const [ldapTestUsername, setLDAPTestUsername] = useState('')
  const [ldapTestPassword, setLDAPTestPassword] = useState('')
  const [ldapTestBusy, setLDAPTestBusy] = useState(false)
  const [wecomSettings, setWeComSettings] = useState<WeComSettingsState>(() => defaultWeComSettings())
  const [wecomBusy, setWeComBusy] = useState(false)
  const [wecomTestBusy, setWeComTestBusy] = useState(false)
  const [passwordForm, setPasswordForm] = useState({ currentPassword: '', newPassword: '', confirmPassword: '' })
  const [passwordBusy, setPasswordBusy] = useState(false)
  const [licenseInfo, setLicenseInfo] = useState<LocalLicenseInfo | null>(null)
  const [licenseForm, setLicenseForm] = useState<LocalLicenseFormState>(() => defaultLocalLicenseForm())
  const [licenseBusy, setLicenseBusy] = useState(false)
  const showPermissionDenied = () => app.showToast(t('permissionDenied', { defaultValue: 'Permission denied' }))

  const loadMFAStatus = async () => {
    setMFAStatus(await apiRequest<MFAStatus>('/api/auth/mfa/status'))
  }

  const loadPasskeys = async () => {
    const result = await apiRequest<{ items: PasskeyItem[] }>('/api/auth/passkeys')
    setPasskeys(result.items || [])
  }

  const loadSSHPublicKeys = async () => {
    const result = await apiRequest<{ items: SSHPublicKeyItem[] }>('/api/auth/ssh-keys')
    setSSHPublicKeys(result.items || [])
  }

  const loadLoginSecurity = async () => {
    const result = await apiRequest<{ items: PlatformItem[] }>('/api/admin/system-settings')
    setLoginSecurity(loginSecurityFromSettings(result.items, app.captchaRequired, app.passwordLoginDisabled))
    setRetentionSettings(retentionSettingsFromSettings(result.items))
    setOIDCSettings(oidcSettingsFromSettings(result.items))
    setLDAPSettings(ldapSettingsFromSettings(result.items))
    setWeComSettings(wecomSettingsFromSettings(result.items))
  }

  const loadLoginPolicies = async () => {
    const result = await apiRequest<{ items: PlatformItem[] }>('/api/admin/login-policies')
    setLoginPolicies(result.items || [])
  }

  const loadLoginLocks = async () => {
    const result = await apiRequest<{ items: PlatformItem[] }>('/api/admin/login-locked')
    setLoginLocks(result.items || [])
  }

  const loadLocalLicense = async () => {
    const result = await apiRequest<LocalLicenseInfo>('/api/admin/license')
    setLicenseInfo(result)
    setLicenseForm(localLicenseFormFromInfo(result))
  }

  useEffect(() => {
    void loadMFAStatus().catch(() => undefined)
    void loadPasskeys().catch(() => undefined)
    void loadSSHPublicKeys().catch(() => undefined)
    if (canReadSystemSettings) {
      void loadLoginSecurity().catch(() => undefined)
    }
    if (canReadLoginPolicies) {
      void loadLoginPolicies().catch(() => undefined)
    }
    if (canReadLoginLocks) {
      void loadLoginLocks().catch(() => undefined)
    }
    if (canReadLicense) {
      void loadLocalLicense().catch(() => undefined)
    }
  }, [canReadSystemSettings, canReadLoginPolicies, canReadLoginLocks, canReadLicense])

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

  const changePassword = async () => {
    if (passwordForm.newPassword !== passwordForm.confirmPassword) {
      app.showToast(t('auth.passwordMismatch'))
      return
    }
    if (passwordForm.newPassword.length < 8) {
      app.showToast(t('settingsPage.passwordTooShort'))
      return
    }
    setPasswordBusy(true)
    try {
      await apiRequest('/api/auth/password', {
        method: 'POST',
        body: JSON.stringify({
          current_password: passwordForm.currentPassword,
          new_password: passwordForm.newPassword,
        }),
      })
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' })
      app.showToast(t('settingsPage.passwordChanged'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setPasswordBusy(false)
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
      setMFARecoveryCodes(result.recovery_codes || [])
      app.showToast(t('settingsPage.mfaEnabled'))
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
      setMFARecoveryCodes([])
      await loadMFAStatus()
      app.showToast(t('settingsPage.mfaDisabled'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setMFABusy(false)
    }
  }

  const regenerateMFARecoveryCodes = async () => {
    setMFABusy(true)
    try {
      const result = await apiRequest<{ recovery_codes: string[]; recovery_count: number }>('/api/auth/mfa/recovery-codes', {
        method: 'POST',
        body: JSON.stringify({ current_password: mfaPassword, mfa_code: mfaCode }),
      })
      setMFACode('')
      setMFAPassword('')
      setMFARecoveryCodes(result.recovery_codes || [])
      await loadMFAStatus()
      app.showToast(t('settingsPage.mfaRecoveryCodesRegenerated'))
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
        body: JSON.stringify(passkeyAttestationPayload(credential as PublicKeyCredential, options.challenge_id, passkeyName.trim() || t('settingsPage.defaultPasskeyName', { defaultValue: 'Passkey' }))),
      })
      setPasskeyName('')
      await loadPasskeys()
      app.showToast(t('settingsPage.passkeyRegistered', { defaultValue: 'Passkey registered.' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setPasskeyBusy(false)
    }
  }

  const deletePasskey = async (item: PasskeyItem) => {
    const confirmed = await confirm({
      title: t('settingsPage.passkeyDeleteConfirm', { defaultValue: 'Delete this passkey?' }),
      description: t('settingsPage.passkeyDeleteDescription', { defaultValue: 'This passkey can no longer be used to sign in after deletion.' }),
      confirmText: t('settingsPage.deletePasskey', { defaultValue: 'Delete passkey' }),
      destructive: true,
    })
    if (!confirmed) return
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

  const registerSSHPublicKey = async () => {
    if (!sshPublicKeyForm.publicKey.trim()) return
    setSSHPublicKeyBusy(true)
    try {
      await apiRequest<SSHPublicKeyItem>('/api/auth/ssh-keys', {
        method: 'POST',
        body: JSON.stringify({ name: sshPublicKeyForm.name, public_key: sshPublicKeyForm.publicKey }),
      })
      setSSHPublicKeyForm({ name: '', publicKey: '' })
      await loadSSHPublicKeys()
      app.showToast(t('settingsPage.sshPublicKeyRegistered', { defaultValue: 'SSH public key registered.' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSSHPublicKeyBusy(false)
    }
  }

  const deleteSSHPublicKey = async (item: SSHPublicKeyItem) => {
    const confirmed = await confirm({
      title: t('settingsPage.sshPublicKeyDeleteConfirm', { defaultValue: 'Delete this SSH public key?' }),
      description: t('settingsPage.sshPublicKeyDeleteDescription', { defaultValue: 'Clients using this key can no longer sign in to the native SSH gateway.' }),
      confirmText: t('settingsPage.deleteSSHPublicKey', { defaultValue: 'Delete SSH key' }),
      destructive: true,
    })
    if (!confirmed) return
    setSSHPublicKeyBusy(true)
    try {
      await apiRequest(`/api/auth/ssh-keys/${item.id}`, { method: 'DELETE' })
      await loadSSHPublicKeys()
      app.showToast(t('settingsPage.sshPublicKeyDeleted', { defaultValue: 'SSH public key deleted.' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSSHPublicKeyBusy(false)
    }
  }

  const updateLoginSecurity = async (next: Partial<LoginSecurityState>) => {
    if (!canReadSystemSettings) {
      showPermissionDenied()
      return
    }
    setLoginSecurityBusy(true)
    try {
      const merged = {
        ...loginSecurity,
        ...next,
        loginFailureThreshold: clampSettingNumber(next.loginFailureThreshold ?? loginSecurity.loginFailureThreshold, 1, 50, 5),
        loginFailureWindowMinutes: clampSettingNumber(next.loginFailureWindowMinutes ?? loginSecurity.loginFailureWindowMinutes, 1, 1440, 15),
        loginLockMinutes: clampSettingNumber(next.loginLockMinutes ?? loginSecurity.loginLockMinutes, 1, 1440, 5),
      }
      const result = await apiRequest<{ items: PlatformItem[] }>('/api/admin/system-settings')
      const current = loginSecurityFromSettings(result.items, app.captchaRequired, app.passwordLoginDisabled)
      const target = current.setting
      if (!canSaveSystemSetting(target?.id)) {
        showPermissionDenied()
        return
      }
      const metadata = {
        ...(target?.metadata ?? {}),
        captcha_enabled: merged.captchaEnabled,
        disable_password_login: merged.passwordLoginDisabled,
        password_login: !merged.passwordLoginDisabled,
        force_mfa: merged.forceMFARequired,
        login_failure_threshold: merged.loginFailureThreshold,
        login_failure_window_minutes: merged.loginFailureWindowMinutes,
        login_lock_minutes: merged.loginLockMinutes,
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
      await loadMFAStatus()
      app.showToast(t('saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoginSecurityBusy(false)
    }
  }

  const patchRetentionSettings = (key: RetentionNumberKey, value: number) => {
    setRetentionSettings((current) => ({
      ...current,
      [key]: clampSettingNumber(value, 0, 36500, 90),
    }))
  }

  const saveRetentionSettings = async () => {
    if (!canSaveSystemSetting(retentionSettings.setting?.id)) {
      showPermissionDenied()
      return
    }
    setRetentionBusy(true)
    try {
      const payload = {
        name: retentionSettings.setting?.name || 'Log retention',
        type: 'retention',
        status: 'enabled',
        metadata: {
          connection_sessions_days: retentionSettings.sessionDays,
          login_logs_days: retentionSettings.loginDays,
          scheduled_task_logs_days: retentionSettings.scheduledTaskDays,
          operation_logs_days: retentionSettings.operationDays,
          file_logs_days: retentionSettings.fileDays,
          access_logs_days: retentionSettings.accessDays,
          sql_logs_days: retentionSettings.sqlDays,
          exec_command_logs_days: retentionSettings.execCommandDays,
        },
      }
      if (retentionSettings.setting?.id) {
        await apiRequest<PlatformItem>(`/api/admin/system-settings/${retentionSettings.setting.id}`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        })
      } else {
        await apiRequest<PlatformItem>('/api/admin/system-settings', {
          method: 'POST',
          body: JSON.stringify(payload),
        })
      }
      await loadLoginSecurity()
      app.showToast(t('settingsPage.retentionSaved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setRetentionBusy(false)
    }
  }

  const createLoginPolicy = async () => {
    if (!canCreateLoginPolicy) {
      showPermissionDenied()
      return
    }
    const cidr = loginPolicyForm.cidr.trim()
    if (!cidr) {
      app.showToast(t('settingsPage.loginPolicyCidrRequired', { defaultValue: 'IP or CIDR is required.' }))
      return
    }
    setLoginPolicyBusy(true)
    try {
      const action = loginPolicyForm.action === 'allow' ? 'allow' : 'deny'
      const account = loginPolicyForm.account.trim() || '*'
      const expiresAt = loginPolicyForm.expiresAt.trim()
      await apiRequest<PlatformItem>('/api/admin/login-policies', {
        method: 'POST',
        body: JSON.stringify({
          name: loginPolicyForm.name.trim() || `${action.toUpperCase()} ${cidr}`,
          type: action,
          status: 'enabled',
          username: account,
          host: cidr,
          description: action === 'allow' ? 'allow login from matched clients' : 'deny login from matched clients',
          metadata: {
            action,
            account,
            cidr,
            priority: loginPolicyForm.priority,
            ...(expiresAt ? { expires_at: new Date(expiresAt).toISOString() } : {}),
          },
        }),
      })
      setLoginPolicyForm(defaultLoginPolicyForm)
      await loadLoginPolicies()
      app.showToast(t('saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoginPolicyBusy(false)
    }
  }

  const toggleLoginPolicy = async (policy: PlatformItem) => {
    if (!canPatchLoginPolicy(policy.id)) {
      showPermissionDenied()
      return
    }
    setLoginPolicyBusy(true)
    try {
      await apiRequest<PlatformItem>(`/api/admin/login-policies/${policy.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          name: policy.name,
          type: loginPolicyAction(policy),
          status: platformItemEnabled(policy) ? 'disabled' : 'enabled',
          username: policy.username || loginPolicyAccount(policy),
          host: policy.host || loginPolicyCIDR(policy),
          description: policy.description || '',
          metadata: {
            ...(policy.metadata ?? {}),
            action: loginPolicyAction(policy),
            account: loginPolicyAccount(policy),
            cidr: loginPolicyCIDR(policy),
          },
        }),
      })
      await loadLoginPolicies()
      app.showToast(t('saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoginPolicyBusy(false)
    }
  }

  const deleteLoginPolicy = async (policy: PlatformItem) => {
    if (!canDeleteLoginPolicy(policy.id)) {
      showPermissionDenied()
      return
    }
    setLoginPolicyBusy(true)
    try {
      await apiRequest(`/api/admin/login-policies/${policy.id}`, { method: 'DELETE' })
      await loadLoginPolicies()
      app.showToast(t('settingsPage.loginPolicyDeleted'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoginPolicyBusy(false)
    }
  }

  const unlockLoginLock = async (lock: PlatformItem) => {
    if (!canDeleteLoginLock(lock.id)) {
      showPermissionDenied()
      return
    }
    setLoginLockBusy(true)
    try {
      await apiRequest(`/api/admin/login-locked/${lock.id}`, { method: 'DELETE' })
      await loadLoginLocks()
      app.showToast(t('settingsPage.loginLockUnlocked'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoginLockBusy(false)
    }
  }

  const patchLDAP = (next: Partial<LDAPSettingsState>) => setLDAPSettings((current) => ({ ...current, ...next }))
  const patchOIDC = (next: Partial<OIDCSettingsState>) => setOIDCSettings((current) => ({ ...current, ...next }))
  const patchWeCom = (next: Partial<WeComSettingsState>) => setWeComSettings((current) => ({ ...current, ...next }))

  const saveOIDCSettings = async () => {
    if (!canSaveSystemSetting(oidcSettings.setting?.id)) {
      showPermissionDenied()
      return
    }
    if (!oidcFormValid) {
      app.showToast(t('settingsPage.oidcConfigurationInvalid', { defaultValue: 'Complete the OIDC connection settings before saving.' }))
      return
    }
    setOIDCBusy(true)
    try {
      const target = oidcSettings.setting
      const metadata: Record<string, unknown> = {
        ...(target?.metadata ?? {}),
        oidc_login_enabled: oidcSettings.enabled,
        oidc_provider_id: 'default-oidc',
        oidc_provider_name: oidcSettings.providerName.trim() || 'OIDC',
        oidc_issuer: oidcSettings.issuer.trim(),
        oidc_authorization_endpoint: oidcSettings.authorizationEndpoint.trim(),
        oidc_token_endpoint: oidcSettings.tokenEndpoint.trim(),
        oidc_userinfo_endpoint: oidcSettings.userInfoEndpoint.trim(),
        oidc_jwks_uri: oidcSettings.jwksEndpoint.trim(),
        oidc_client_id: oidcSettings.clientID.trim(),
        oidc_scopes: oidcSettings.scopes.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean),
        oidc_token_endpoint_auth_method: oidcSettings.tokenAuthMethod,
        oidc_require_id_token: oidcSettings.requireIDToken,
        oidc_role: oidcSettings.role || 'user',
        oidc_auto_create: oidcSettings.autoCreate,
      }
      if (oidcSettings.clientSecret.trim()) metadata.oidc_client_secret = oidcSettings.clientSecret.trim()
      else if (oidcSettings.clientSecretClear) metadata.oidc_client_secret_clear = true
      const payload = {
        name: target?.name || 'External OIDC identity',
        type: 'identity',
        status: 'enabled',
        metadata,
      }
      let saved: PlatformItem
      if (target?.id) {
        saved = await apiRequest<PlatformItem>(`/api/admin/system-settings/${target.id}`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        })
      } else {
        saved = await apiRequest<PlatformItem>('/api/admin/system-settings', {
          method: 'POST',
          body: JSON.stringify(payload),
        })
      }
      patchOIDC({
        clientSecret: '',
        clientSecretSet: Boolean(saved.metadata?.oidc_client_secret_set),
        clientSecretClear: false,
        setting: saved,
      })
      await app.refresh(true)
      await loadLoginSecurity()
      app.showToast(t('saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setOIDCBusy(false)
    }
  }

  const testOIDCSettings = async () => {
    if (!canTestOIDCSettings) {
      showPermissionDenied()
      return
    }
    setOIDCTestBusy(true)
    try {
      await apiRequest('/api/admin/system-settings/oidc/test', {
        method: 'POST',
        body: JSON.stringify({ setting_id: oidcSettings.setting?.id }),
      })
      app.showToast(t('settingsPage.oidcTestSucceeded', { defaultValue: 'OIDC authorization endpoint test succeeded' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setOIDCTestBusy(false)
    }
  }

  const saveLDAPSettings = async () => {
    if (!canSaveSystemSetting(ldapSettings.setting?.id)) {
      showPermissionDenied()
      return
    }
    if (!ldapFormValid) {
      app.showToast(t('settingsPage.ldapConfigurationInvalid', { defaultValue: 'Complete the LDAP connection settings before saving.' }))
      return
    }
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
        ldap_user_dn_template: ldapSettings.userDNTemplate.trim(),
        ldap_username_attribute: ldapSettings.usernameAttribute.trim() || 'uid',
        ldap_display_name_attribute: ldapSettings.displayNameAttribute.trim() || 'cn',
        ldap_email_attribute: ldapSettings.emailAttribute.trim() || 'mail',
        ldap_role: ldapSettings.role || 'user',
        ldap_auto_create: ldapSettings.autoCreate,
        ldap_start_tls: ldapSettings.startTLS,
        ldap_server_name: ldapSettings.serverName.trim(),
        ldap_insecure_skip_verify: ldapSettings.insecureSkipVerify,
      }
      if (ldapSettings.bindPassword.trim()) metadata.ldap_bind_password = ldapSettings.bindPassword.trim()
      else if (ldapSettings.bindPasswordClear) metadata.ldap_bind_password_clear = true
      const payload = {
        name: target?.name || 'LDAP identity',
        type: 'identity',
        status: 'enabled',
        metadata,
      }
      let saved: PlatformItem
      if (target?.id) {
        saved = await apiRequest<PlatformItem>(`/api/admin/system-settings/${target.id}`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        })
      } else {
        saved = await apiRequest<PlatformItem>('/api/admin/system-settings', {
          method: 'POST',
          body: JSON.stringify(payload),
        })
      }
      patchLDAP({
        bindPassword: '',
        bindPasswordSet: Boolean(saved.metadata?.ldap_bind_password_set),
        bindPasswordClear: false,
        setting: saved,
      })
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
    if (!canTestLDAPSettings) {
      showPermissionDenied()
      return
    }
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
    if (!canSaveSystemSetting(wecomSettings.setting?.id)) {
      showPermissionDenied()
      return
    }
    if (!wecomFormValid) {
      app.showToast(t('settingsPage.wecomConfigurationInvalid', { defaultValue: 'Complete the Enterprise WeChat connection settings before saving.' }))
      return
    }
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
      else if (wecomSettings.agentSecretClear) metadata.wecom_agent_secret_clear = true
      const payload = {
        name: target?.name || 'Enterprise WeChat identity',
        type: 'identity',
        status: 'enabled',
        metadata,
      }
      let saved: PlatformItem
      if (target?.id) {
        saved = await apiRequest<PlatformItem>(`/api/admin/system-settings/${target.id}`, {
          method: 'PATCH',
          body: JSON.stringify(payload),
        })
      } else {
        saved = await apiRequest<PlatformItem>('/api/admin/system-settings', {
          method: 'POST',
          body: JSON.stringify(payload),
        })
      }
      patchWeCom({
        agentSecret: '',
        agentSecretSet: Boolean(saved.metadata?.wecom_agent_secret_set),
        agentSecretClear: false,
        setting: saved,
      })
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
    if (!canTestWeComSettings) {
      showPermissionDenied()
      return
    }
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

  const patchLicenseForm = (next: Partial<LocalLicenseFormState>) => setLicenseForm((current) => ({ ...current, ...next }))

  const saveLocalLicense = async () => {
    if (!canSaveLicense) {
      showPermissionDenied()
      return
    }
    setLicenseBusy(true)
    try {
      const result = await apiRequest<LocalLicenseInfo>('/api/admin/license', {
        method: 'PUT',
        body: JSON.stringify({
          licensee: licenseForm.licensee.trim(),
          contact: licenseForm.contact.trim(),
          serial: licenseForm.serial.trim(),
          issued_at: licenseForm.issued_at.trim(),
          expires_at: licenseForm.expires_at.trim(),
          notes: licenseForm.notes.trim(),
          features: splitLicenseFeatures(licenseForm.features),
        }),
      })
      setLicenseInfo(result)
      setLicenseForm(localLicenseFormFromInfo(result))
      app.showToast(t('settingsPage.licenseSaved', { defaultValue: 'License information saved' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLicenseBusy(false)
    }
  }

  const canSaveLoginSecurity = canSaveSystemSetting(loginSecurity.setting?.id)
  const canSaveRetentionSettings = canSaveSystemSetting(retentionSettings.setting?.id)
  const canSaveOIDCSettings = canSaveSystemSetting(oidcSettings.setting?.id)
  const canSaveLDAPSettings = canSaveSystemSetting(ldapSettings.setting?.id)
  const canSaveWeComSettings = canSaveSystemSetting(wecomSettings.setting?.id)
  const ldapURLValid = !ldapSettings.url.trim() || isValidLDAPURL(ldapSettings.url)
  const ldapURLFieldInvalid = ldapSettings.enabled && (!ldapSettings.url.trim() || !ldapURLValid)
  const ldapUsesImplicitTLS = ldapSettings.url.trim().toLowerCase().startsWith('ldaps://')
  const ldapTLSModeValid = !(ldapUsesImplicitTLS && ldapSettings.startTLS)
  const ldapSearchBaseReady = Boolean(ldapSettings.baseDN.trim() || ldapSettings.userDNTemplate.trim())
  const ldapFormValid = !ldapSettings.enabled || (Boolean(ldapSettings.url.trim()) && ldapURLValid && ldapTLSModeValid && ldapSearchBaseReady)
  const oidcIssuer = oidcSettings.issuer.trim()
  const oidcAuthorizationEndpoint = oidcSettings.authorizationEndpoint.trim()
  const oidcTokenEndpoint = oidcSettings.tokenEndpoint.trim()
  const oidcUserInfoEndpoint = oidcSettings.userInfoEndpoint.trim()
  const oidcJWKSEndpoint = oidcSettings.jwksEndpoint.trim()
  const oidcClientID = oidcSettings.clientID.trim()
  const oidcScopes = oidcSettings.scopes.split(/[,\s]+/).map((item) => item.trim()).filter(Boolean)
  const oidcIssuerValid = !oidcIssuer || isValidOIDCEndpoint(oidcIssuer, false)
  const oidcAuthorizationEndpointValid = !oidcAuthorizationEndpoint || isValidOIDCEndpoint(oidcAuthorizationEndpoint, true)
  const oidcTokenEndpointValid = !oidcTokenEndpoint || isValidOIDCEndpoint(oidcTokenEndpoint, false)
  const oidcUserInfoEndpointValid = !oidcUserInfoEndpoint || isValidOIDCEndpoint(oidcUserInfoEndpoint, false)
  const oidcJWKSEndpointValid = !oidcJWKSEndpoint || isValidOIDCEndpoint(oidcJWKSEndpoint, false)
  const oidcClientIDValid = !oidcClientID || (!/[\u0000\r\n\t]/.test(oidcClientID) && oidcClientID.length <= 512)
  const oidcScopesValid = oidcScopes.length > 0 && oidcScopes.length <= 32 && oidcScopes.includes('openid') && oidcScopes.every((scope) => scope.length <= 128 && !/\s/.test(scope))
  const oidcClientSecretReady = oidcSettings.tokenAuthMethod === 'none' || Boolean(oidcSettings.clientSecret.trim() || (oidcSettings.clientSecretSet && !oidcSettings.clientSecretClear))
  const oidcIssuerFieldInvalid = !oidcIssuerValid || (oidcSettings.enabled && oidcSettings.requireIDToken && !oidcIssuer)
  const oidcAuthorizationFieldInvalid = !oidcAuthorizationEndpointValid || (oidcSettings.enabled && !oidcAuthorizationEndpoint)
  const oidcTokenFieldInvalid = !oidcTokenEndpointValid || (oidcSettings.enabled && !oidcTokenEndpoint)
  const oidcUserInfoFieldInvalid = !oidcUserInfoEndpointValid || (oidcSettings.enabled && !oidcSettings.requireIDToken && !oidcUserInfoEndpoint)
  const oidcClientIDFieldInvalid = !oidcClientIDValid || (oidcSettings.enabled && !oidcClientID)
  const oidcClientSecretFieldInvalid = oidcSettings.enabled && !oidcClientSecretReady
  const oidcFormValid = oidcIssuerValid && oidcAuthorizationEndpointValid && oidcTokenEndpointValid && oidcUserInfoEndpointValid && oidcJWKSEndpointValid && oidcClientIDValid && oidcScopesValid && (!oidcSettings.enabled || (
    Boolean(oidcAuthorizationEndpoint) && Boolean(oidcTokenEndpoint) && Boolean(oidcClientID) && oidcClientSecretReady && (oidcSettings.requireIDToken ? Boolean(oidcIssuer) : Boolean(oidcUserInfoEndpoint))
  ))
  const wecomCorpID = wecomSettings.corpID.trim()
  const wecomAgentID = wecomSettings.agentID.trim()
  const wecomCorpIDValid = !wecomCorpID || (!/[\s/@?#\\]/.test(wecomCorpID) && wecomCorpID.length <= 256)
  const wecomAgentIDValid = !wecomAgentID || /^\d{1,32}$/.test(wecomAgentID)
  const wecomAgentSecretReady = Boolean(wecomSettings.agentSecret.trim() || (wecomSettings.agentSecretSet && !wecomSettings.agentSecretClear))
  const wecomCorpIDFieldInvalid = !wecomCorpIDValid || (wecomSettings.enabled && !wecomCorpID)
  const wecomAgentSecretFieldInvalid = wecomSettings.enabled && !wecomAgentSecretReady
  const wecomFormValid = wecomCorpIDValid && wecomAgentIDValid && (!wecomSettings.enabled || (Boolean(wecomCorpID) && wecomAgentSecretReady))
  const canShowLoginAccessSection = canReadSystemSettings || canReadLoginPolicies || canReadLoginLocks || canReadLicense

  return (
    <CardStaggerContainer className='grid gap-4'>
      <CardStaggerItem id='settings-profile' className='scroll-mt-20 rounded-xl border border-border bg-card p-5 shadow-sm'>
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
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <KeyRound className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.sshPublicKeysTitle', { defaultValue: 'SSH public keys' })}</h2>
              <Badge tone={sshPublicKeys.length > 0 ? 'success' : 'warning'}>
                {sshPublicKeys.length > 0
                  ? t('settingsPage.sshPublicKeysCount', { defaultValue: '{{count}} registered', count: sshPublicKeys.length })
                  : t('settingsPage.sshPublicKeysEmptyStatus', { defaultValue: 'Not registered' })}
              </Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>
              {t('settingsPage.sshPublicKeysDescription', { defaultValue: 'Register OpenSSH public keys for native SSH gateway login. Private keys remain on your device.' })}
            </p>
          </div>
        </div>
        <div className='grid gap-3'>
          {sshPublicKeys.length ? (
            <div className='grid gap-2'>
              {sshPublicKeys.map((item) => (
                <div key={item.id} className='flex min-w-0 flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-background/70 p-3'>
                  <div className='min-w-0 flex-1'>
                    <div className='flex flex-wrap items-center gap-2'>
                      <span className='truncate text-sm font-medium'>{item.name}</span>
                      <Badge>{item.type}</Badge>
                    </div>
                    <div className='mt-1 truncate font-mono text-xs text-muted-foreground' title={item.fingerprint}>{item.fingerprint}</div>
                    <div className='mt-1 text-xs text-muted-foreground'>{t('createdAt')}: {formatDate(item.created_at)}</div>
                  </div>
                  <Button type='button' variant='ghost' size='icon-sm' onClick={() => void deleteSSHPublicKey(item)} disabled={sshPublicKeyBusy} aria-label={t('settingsPage.deleteSSHPublicKey', { defaultValue: 'Delete SSH key' })}>
                    <Trash2 className='size-4' />
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <div className='rounded-lg border border-dashed border-border bg-background/70 p-3 text-sm text-muted-foreground'>
              {t('settingsPage.sshPublicKeysEmpty', { defaultValue: 'No SSH public keys are registered for this account.' })}
            </div>
          )}
          <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <Field label={t('settingsPage.sshPublicKeyName', { defaultValue: 'Key name' })}>
              <Input value={sshPublicKeyForm.name} onChange={(event) => {
                const value = event.currentTarget.value
                setSSHPublicKeyForm((current) => ({ ...current, name: value }))
              }} placeholder={t('settingsPage.sshPublicKeyNamePlaceholder', { defaultValue: 'Work laptop' })} />
            </Field>
            <Field label={t('settingsPage.sshPublicKeyValue', { defaultValue: 'OpenSSH public key' })}>
              <Textarea className='min-h-24 font-mono text-xs' value={sshPublicKeyForm.publicKey} onChange={(event) => {
                const value = event.currentTarget.value
                setSSHPublicKeyForm((current) => ({ ...current, publicKey: value }))
              }} placeholder='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host' />
            </Field>
            <div className='flex justify-end'>
              <Button variant='primary' onClick={() => void registerSSHPublicKey()} disabled={sshPublicKeyBusy || !sshPublicKeyForm.publicKey.trim()}>
                <KeyRound className='size-4' />
                {sshPublicKeyBusy ? t('saving') : t('settingsPage.registerSSHPublicKey', { defaultValue: 'Register SSH key' })}
              </Button>
            </div>
          </div>
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

        <div className='grid gap-3'>
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
          <form
            className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'
            onSubmit={(event) => {
              event.preventDefault()
              void changePassword()
            }}
          >
            <div>
              <div className='text-sm font-medium'>{t('settingsPage.localPasswordTitle')}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.localPasswordDescription')}</p>
            </div>
            <div className='grid gap-3 md:grid-cols-3'>
              <Field label={t('settingsPage.currentPassword')}>
                <Input
                  type='password'
                  value={passwordForm.currentPassword}
                  onChange={(event) => setPasswordForm((current) => ({ ...current, currentPassword: event.currentTarget.value }))}
                  autoComplete='current-password'
                />
              </Field>
              <Field label={t('settingsPage.newPassword')}>
                <Input
                  type='password'
                  value={passwordForm.newPassword}
                  onChange={(event) => setPasswordForm((current) => ({ ...current, newPassword: event.currentTarget.value }))}
                  autoComplete='new-password'
                  minLength={8}
                />
              </Field>
              <Field label={t('settingsPage.confirmPassword')}>
                <Input
                  type='password'
                  value={passwordForm.confirmPassword}
                  onChange={(event) => setPasswordForm((current) => ({ ...current, confirmPassword: event.currentTarget.value }))}
                  autoComplete='new-password'
                  minLength={8}
                />
              </Field>
            </div>
            <div className='flex justify-end'>
              <Button
                type='submit'
                variant='primary'
                disabled={passwordBusy || !passwordForm.currentPassword || !passwordForm.newPassword || !passwordForm.confirmPassword}
              >
                <KeyRound className='size-4' />
                {passwordBusy ? t('saving') : t('settingsPage.changePassword')}
              </Button>
            </div>
          </form>
        </div>
      </CardStaggerItem>

      {canReadSystemSettings ? (
      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <Globe2 className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.oidcTitle', { defaultValue: 'External OIDC login' })}</h2>
              <Badge tone={oidcSettings.enabled ? 'success' : 'warning'}>
                {oidcSettings.enabled ? t('settingsPage.oidcEnabled', { defaultValue: 'OIDC on' }) : t('settingsPage.oidcDisabled', { defaultValue: 'OIDC off' })}
              </Badge>
              <Badge tone={oidcSettings.clientSecretSet ? 'success' : 'neutral'}>
                {oidcSettings.clientSecretSet
                  ? t('settingsPage.oidcClientSecretSaved', { defaultValue: 'Client secret saved' })
                  : t('settingsPage.oidcClientSecretNotSet', { defaultValue: 'Client secret not set' })}
              </Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>
              {t('settingsPage.oidcDescription', { defaultValue: 'Allow users to sign in through an external OpenID Connect provider. Client secrets are encrypted server-side and never returned by API responses.' })}
            </p>
          </div>
        </div>
        <div className='grid gap-3'>
          <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
            <input
              type='checkbox'
              className='size-4 accent-primary'
              checked={oidcSettings.enabled}
              onChange={(event) => patchOIDC({ enabled: event.currentTarget.checked })}
            />
            <span>{t('settingsPage.oidcEnableLogin', { defaultValue: 'Enable OIDC login' })}</span>
          </label>
          <div className='grid gap-3 md:grid-cols-2'>
            <Field label={t('name')}>
              <Input value={oidcSettings.providerName} onChange={(event) => patchOIDC({ providerName: event.currentTarget.value })} placeholder='Corporate SSO' />
            </Field>
            <Field label={t('settingsPage.oidcClientID', { defaultValue: 'Client ID' })}>
              <Input value={oidcSettings.clientID} onChange={(event) => patchOIDC({ clientID: event.currentTarget.value })} placeholder='openweb-client' maxLength={512} aria-invalid={oidcClientIDFieldInvalid} />
              {oidcClientIDFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.oidcClientIDRequired', { defaultValue: 'A valid Client ID is required while OIDC login is enabled.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.oidcClientSecret', { defaultValue: 'Client secret' })}>
              <Input type='password' value={oidcSettings.clientSecret} onChange={(event) => patchOIDC({ clientSecret: event.currentTarget.value, clientSecretClear: false })} placeholder={oidcSettings.clientSecretSet ? t('settingsPage.keepCurrentSecret') : ''} autoComplete='new-password' aria-invalid={oidcClientSecretFieldInvalid} />
              {oidcClientSecretFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.oidcClientSecretRequired', { defaultValue: 'A Client secret is required for the selected token authentication method.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.oidcScopes', { defaultValue: 'Scopes' })}>
              <Input value={oidcSettings.scopes} onChange={(event) => patchOIDC({ scopes: event.currentTarget.value })} placeholder='openid profile email' aria-invalid={!oidcScopesValid} />
              {!oidcScopesValid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.oidcOpenIDScopeRequired', { defaultValue: 'Scopes must include openid.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.oidcIssuer', { defaultValue: 'Issuer' })}>
              <Input value={oidcSettings.issuer} onChange={(event) => patchOIDC({ issuer: event.currentTarget.value })} placeholder='https://sso.example.com' aria-invalid={oidcIssuerFieldInvalid} />
              {oidcIssuerFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.oidcIssuerInvalid', { defaultValue: 'Enter a valid HTTPS issuer URL without credentials, query, or fragment.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.oidcAuthorizationEndpoint', { defaultValue: 'Authorization endpoint' })}>
              <Input value={oidcSettings.authorizationEndpoint} onChange={(event) => patchOIDC({ authorizationEndpoint: event.currentTarget.value })} placeholder='https://sso.example.com/oauth2/authorize' aria-invalid={oidcAuthorizationFieldInvalid} />
              {oidcAuthorizationFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.oidcEndpointInvalid', { defaultValue: 'Enter a valid HTTPS endpoint URL.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.oidcTokenEndpoint', { defaultValue: 'Token endpoint' })}>
              <Input value={oidcSettings.tokenEndpoint} onChange={(event) => patchOIDC({ tokenEndpoint: event.currentTarget.value })} placeholder='https://sso.example.com/oauth2/token' aria-invalid={oidcTokenFieldInvalid} />
              {oidcTokenFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.oidcEndpointInvalid', { defaultValue: 'Enter a valid HTTPS endpoint URL.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.oidcUserInfoEndpoint', { defaultValue: 'UserInfo endpoint' })}>
              <Input value={oidcSettings.userInfoEndpoint} onChange={(event) => patchOIDC({ userInfoEndpoint: event.currentTarget.value })} placeholder='https://sso.example.com/oauth2/userinfo' aria-invalid={oidcUserInfoFieldInvalid} />
              {oidcUserInfoFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.oidcUserInfoRequired', { defaultValue: 'UserInfo is required when ID token verification is disabled.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.oidcJWKSEndpoint', { defaultValue: 'JWKS URI' })}>
              <Input value={oidcSettings.jwksEndpoint} onChange={(event) => patchOIDC({ jwksEndpoint: event.currentTarget.value })} placeholder='https://sso.example.com/oauth2/jwks' aria-invalid={!oidcJWKSEndpointValid} />
              {!oidcJWKSEndpointValid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.oidcEndpointInvalid', { defaultValue: 'Enter a valid HTTPS endpoint URL.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.oidcAuthMethod', { defaultValue: 'Token auth method' })}>
              <Select value={oidcSettings.tokenAuthMethod} onChange={(event) => patchOIDC({ tokenAuthMethod: event.currentTarget.value as OIDCSettingsState['tokenAuthMethod'] })}>
                <option value='client_secret_basic'>client_secret_basic</option>
                <option value='client_secret_post'>client_secret_post</option>
                <option value='none'>{t('settingsPage.oidcPublicClient', { defaultValue: 'none (public client)' })}</option>
              </Select>
            </Field>
            <Field label={t('settingsPage.defaultRole', { defaultValue: 'Default role' })}>
              <Select value={oidcSettings.role} onChange={(event) => patchOIDC({ role: event.currentTarget.value })}>
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
              checked={oidcSettings.requireIDToken}
              onChange={(event) => patchOIDC({ requireIDToken: event.currentTarget.checked })}
            />
            <span>{t('settingsPage.oidcRequireIDToken', { defaultValue: 'Require and verify ID Token' })}</span>
          </label>
          <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
            <input
              type='checkbox'
              className='size-4 accent-primary'
              checked={oidcSettings.autoCreate}
              onChange={(event) => patchOIDC({ autoCreate: event.currentTarget.checked })}
            />
            <span>{t('settingsPage.oidcAutoCreate', { defaultValue: 'Create OIDC users on first successful login' })}</span>
          </label>
          {oidcSettings.clientSecretSet && (
            <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
              <input
                type='checkbox'
                className='size-4 accent-primary'
                checked={oidcSettings.clientSecretClear}
                onChange={(event) => patchOIDC({ clientSecretClear: event.currentTarget.checked, clientSecret: event.currentTarget.checked ? '' : oidcSettings.clientSecret })}
              />
              <span>{t('settingsPage.clearOIDCClientSecret', { defaultValue: 'Clear saved OIDC client secret on save' })}</span>
            </label>
          )}
          <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div>
              <div className='text-sm font-medium'>{t('settingsPage.oidcTestTitle', { defaultValue: 'Test OIDC authorization endpoint' })}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.oidcTestDescription', { defaultValue: 'Validate the saved authorization endpoint, client ID, redirect URI, and scopes by starting a no-redirect OIDC authorization request.' })}</p>
            </div>
            <div className='flex justify-end'>
              {canTestOIDCSettings ? (
                <Button
                  variant='outline'
                  onClick={() => void testOIDCSettings()}
                  disabled={oidcTestBusy || !oidcSettings.setting?.id}
                >
                  {oidcTestBusy ? t('testing') : t('settingsPage.testOIDC', { defaultValue: 'Test OIDC' })}
                </Button>
              ) : null}
            </div>
          </div>
          {canSaveOIDCSettings ? (
            <div className='flex justify-end'>
              <Button variant='primary' onClick={() => void saveOIDCSettings()} disabled={oidcBusy || !oidcFormValid}>
                {oidcBusy ? t('saving') : t('save')}
              </Button>
            </div>
          ) : null}
        </div>
      </CardStaggerItem>
      ) : null}

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
          <div className='grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end'>
            <Field label={t('settingsPage.passkeyName', { defaultValue: 'Passkey name' })}>
              <Input value={passkeyName} onChange={(event) => setPasskeyName(event.currentTarget.value)} maxLength={128} placeholder={t('settingsPage.passkeyNamePlaceholder', { defaultValue: 'Work laptop' })} />
            </Field>
            <Button variant='primary' onClick={() => void registerPasskey()} disabled={passkeyBusy || passkeys.length >= maxPasskeysPerUser || !passkeySupported() || !passkeySecureContext()}>
              <Fingerprint className='size-4' />
              {passkeyBusy ? t('saving') : t('settingsPage.registerPasskey', { defaultValue: 'Register passkey' })}
            </Button>
          </div>
          {passkeys.length >= maxPasskeysPerUser ? <p className='text-xs text-destructive'>{t('settingsPage.passkeyLimitReached', { defaultValue: 'This account has reached the 20-passkey limit.' })}</p> : null}
        </div>
      </CardStaggerItem>

      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <ShieldCheck className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.mfaTitle')}</h2>
              <Badge tone={mfaStatus?.enabled ? 'success' : 'warning'}>
                {mfaStatus?.enabled ? t('settingsPage.mfaEnabledStatus') : t('settingsPage.mfaDisabledStatus')}
              </Badge>
              {mfaStatus?.forced ? <Badge tone='danger'>{t('settingsPage.mfaRequiredStatus')}</Badge> : null}
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>{t('settingsPage.mfaDescription')}</p>
            <p className='mt-2 text-xs text-muted-foreground'>{t('settingsPage.mfaRecoveryRemaining', { count: mfaStatus?.recovery_count ?? 0 })}</p>
          </div>
        </div>
        <div className='grid gap-3'>
          {mfaRecoveryCodes.length ? (
            <div className='grid gap-2 rounded-lg border border-warning/35 bg-warning/10 p-3'>
              <div className='text-sm font-medium'>{t('settingsPage.mfaRecoveryCodesTitle')}</div>
              <p className='text-xs leading-5 text-muted-foreground'>{t('settingsPage.mfaRecoveryCodesDescription')}</p>
              <div className='grid gap-1 rounded-md border border-border bg-background/80 p-3 font-mono text-xs sm:grid-cols-2'>
                {mfaRecoveryCodes.map((code) => (
                  <span key={code}>{code}</span>
                ))}
              </div>
            </div>
          ) : null}
          {mfaSetup ? (
            <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
              <Field label={t('settingsPage.mfaTotpSecret')}>
                <Input readOnly className='font-mono text-xs' value={mfaSetup.secret} />
              </Field>
              <Field label={t('settingsPage.mfaOtpauthUrl')}>
                <Input readOnly className='font-mono text-xs' value={mfaSetup.otpauth_url} />
              </Field>
              <Field label={t('settingsPage.mfaCurrentCode')}>
                <Input value={mfaCode} onChange={(event) => setMFACode(event.currentTarget.value)} inputMode='numeric' placeholder='123456' />
              </Field>
              <div className='flex flex-wrap justify-end gap-2'>
                <Button variant='outline' onClick={() => setMFASetup(null)} disabled={mfaBusy}>{t('cancel')}</Button>
                <Button variant='primary' onClick={() => void enableMFA()} disabled={mfaBusy || !mfaCode.trim()}>{t('settingsPage.enableMFA')}</Button>
              </div>
            </div>
          ) : mfaStatus?.enabled ? (
            <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
              <Field label={t('settingsPage.currentPassword')}>
                <Input type='password' value={mfaPassword} onChange={(event) => setMFAPassword(event.currentTarget.value)} />
              </Field>
              <Field label={t('settingsPage.mfaCurrentCode')}>
                <Input value={mfaCode} onChange={(event) => setMFACode(event.currentTarget.value)} inputMode='numeric' placeholder='123456' />
              </Field>
              <div className='flex flex-wrap justify-end gap-2'>
                <Button variant='outline' onClick={() => void regenerateMFARecoveryCodes()} disabled={mfaBusy || !mfaPassword.trim() || !mfaCode.trim()}>
                  {t('settingsPage.regenerateRecoveryCodes')}
                </Button>
                <Button variant='destructive' onClick={() => void disableMFA()} disabled={mfaBusy || !mfaPassword.trim() || !mfaCode.trim()}>
                  {t('settingsPage.disableMFA')}
                </Button>
              </div>
            </div>
          ) : (
            <div className='flex justify-end'>
              <Button variant='primary' onClick={() => void startMFASetup()} disabled={mfaBusy}>{t('settingsPage.setupMFA')}</Button>
            </div>
          )}
        </div>
      </CardStaggerItem>

      {canShowLoginAccessSection ? (
      <>
      {canReadSystemSettings ? (
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
              <Badge tone={loginSecurity.forceMFARequired ? 'danger' : 'neutral'}>
                {loginSecurity.forceMFARequired ? t('settingsPage.forceMFAEnabled') : t('settingsPage.forceMFADisabled')}
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
            {canSaveLoginSecurity ? (
              <Button
                variant={loginSecurity.captchaEnabled ? 'outline' : 'primary'}
                onClick={() => void updateLoginSecurity({ captchaEnabled: !loginSecurity.captchaEnabled })}
                disabled={loginSecurityBusy}
              >
                {loginSecurity.captchaEnabled ? t('settingsPage.disableCaptcha') : t('settingsPage.enableCaptcha')}
              </Button>
            ) : null}
          </div>
          <div className='flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div className='min-w-0'>
              <div className='text-sm font-medium'>{t('settingsPage.passwordLoginTitle')}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.passwordLoginDescription')}</p>
            </div>
            {canSaveLoginSecurity ? (
              <Button
                variant={loginSecurity.passwordLoginDisabled ? 'primary' : 'destructive'}
                onClick={() => void updateLoginSecurity({ passwordLoginDisabled: !loginSecurity.passwordLoginDisabled })}
                disabled={loginSecurityBusy}
              >
                {loginSecurity.passwordLoginDisabled ? t('settingsPage.enablePasswordLogin') : t('settingsPage.disablePasswordLogin')}
              </Button>
            ) : null}
          </div>
          <div className='flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div className='min-w-0'>
              <div className='text-sm font-medium'>{t('settingsPage.forceMFATitle')}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.forceMFADescription')}</p>
            </div>
            {canSaveLoginSecurity ? (
              <Button
                variant={loginSecurity.forceMFARequired ? 'outline' : 'primary'}
                onClick={() => void updateLoginSecurity({ forceMFARequired: !loginSecurity.forceMFARequired })}
                disabled={loginSecurityBusy}
              >
                {loginSecurity.forceMFARequired ? t('settingsPage.disableForceMFA') : t('settingsPage.enableForceMFA')}
              </Button>
            ) : null}
          </div>
          <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div>
              <div className='text-sm font-medium'>{t('settingsPage.lockoutPolicyTitle')}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.lockoutPolicyDescription')}</p>
            </div>
            <div className='grid gap-3 sm:grid-cols-3'>
              <Field label={t('settingsPage.failureThreshold')}>
                <Input
                  type='number'
                  min={1}
                  max={50}
                  value={loginSecurity.loginFailureThreshold}
                  onChange={(event) =>
                    setLoginSecurity((current) => ({
                      ...current,
                      loginFailureThreshold: numberInputValue(event.currentTarget.value, current.loginFailureThreshold),
                    }))
                  }
                />
              </Field>
              <Field label={t('settingsPage.failureWindowMinutes')}>
                <Input
                  type='number'
                  min={1}
                  max={1440}
                  value={loginSecurity.loginFailureWindowMinutes}
                  onChange={(event) =>
                    setLoginSecurity((current) => ({
                      ...current,
                      loginFailureWindowMinutes: numberInputValue(event.currentTarget.value, current.loginFailureWindowMinutes),
                    }))
                  }
                />
              </Field>
              <Field label={t('settingsPage.lockDurationMinutes')}>
                <Input
                  type='number'
                  min={1}
                  max={1440}
                  value={loginSecurity.loginLockMinutes}
                  onChange={(event) =>
                    setLoginSecurity((current) => ({
                      ...current,
                      loginLockMinutes: numberInputValue(event.currentTarget.value, current.loginLockMinutes),
                    }))
                  }
                />
              </Field>
            </div>
            {canSaveLoginSecurity ? (
              <div className='flex justify-end'>
                <Button
                  variant='primary'
                  onClick={() => void updateLoginSecurity({})}
                  disabled={loginSecurityBusy}
                >
                  {t('settingsPage.saveLoginSecurityPolicy')}
                </Button>
              </div>
            ) : null}
          </div>
        </div>
      </CardStaggerItem>
      ) : null}

      {(canReadLoginPolicies || canReadLoginLocks) ? (
      <CardStaggerItem id='settings-login-security' className='scroll-mt-20 grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <ShieldCheck className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.loginPoliciesTitle')}</h2>
              <Badge tone={loginPolicies.some(platformItemEnabled) ? 'success' : 'neutral'}>
                {t('settingsPage.loginPoliciesCount', { count: loginPolicies.filter(platformItemEnabled).length })}
              </Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>{t('settingsPage.loginPoliciesDescription')}</p>
          </div>
        </div>
        <div className='grid gap-3'>
          {canCreateLoginPolicy ? (
            <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
              <div className='grid gap-3 sm:grid-cols-[1fr_0.7fr]'>
                <Field label={t('settingsPage.loginPolicyName')}>
                  <Input
                    value={loginPolicyForm.name}
                    onChange={(event) => {
                      const value = event.currentTarget.value
                      setLoginPolicyForm((current) => ({ ...current, name: value }))
                    }}
                    placeholder={t('settingsPage.loginPolicyNamePlaceholder')}
                  />
                </Field>
                <Field label={t('settingsPage.loginPolicyAction')}>
                  <Select
                    value={loginPolicyForm.action}
                    onChange={(event) => {
                      const value = event.currentTarget.value
                      setLoginPolicyForm((current) => ({ ...current, action: value === 'allow' ? 'allow' : 'deny' }))
                    }}
                  >
                    <option value='deny'>{t('settingsPage.loginPolicyDeny')}</option>
                    <option value='allow'>{t('settingsPage.loginPolicyAllow')}</option>
                  </Select>
                </Field>
              </div>
              <div className='grid gap-3 sm:grid-cols-2'>
                <Field label={t('settingsPage.loginPolicyAccount')}>
                  <Input
                    value={loginPolicyForm.account}
                    onChange={(event) => {
                      const value = event.currentTarget.value
                      setLoginPolicyForm((current) => ({ ...current, account: value }))
                    }}
                    placeholder='*'
                  />
                </Field>
                <Field label={t('settingsPage.loginPolicyCIDR')}>
                  <Input
                    value={loginPolicyForm.cidr}
                    onChange={(event) => {
                      const value = event.currentTarget.value
                      setLoginPolicyForm((current) => ({ ...current, cidr: value }))
                    }}
                    placeholder='192.0.2.0/24'
                  />
                </Field>
                <Field label={t('settingsPage.loginPolicyPriority')}>
                  <Input
                    type='number'
                    value={loginPolicyForm.priority}
                    onChange={(event) => {
                      const value = event.currentTarget.value
                      setLoginPolicyForm((current) => ({ ...current, priority: numberInputValue(value, current.priority) }))
                    }}
                  />
                </Field>
                <Field label={t('settingsPage.loginPolicyExpiresAt')}>
                  <Input
                    type='datetime-local'
                    value={loginPolicyForm.expiresAt}
                    onInput={(event) => {
                      const value = event.currentTarget.value
                      setLoginPolicyForm((current) => ({ ...current, expiresAt: value }))
                    }}
                  />
                </Field>
              </div>
              <div className='flex justify-end'>
                <Button variant='primary' onClick={() => void createLoginPolicy()} disabled={loginPolicyBusy || !loginPolicyForm.cidr.trim()}>
                  {t('settingsPage.createLoginPolicy')}
                </Button>
              </div>
            </div>
          ) : null}
          {canReadLoginPolicies ? (
            <div className='overflow-hidden rounded-lg border border-border bg-background/70'>
              {loginPolicies.length === 0 ? (
                <div className='p-4 text-sm text-muted-foreground'>{t('settingsPage.loginPoliciesEmpty')}</div>
              ) : (
                <div className='divide-y divide-border'>
                  {loginPolicies.map((policy) => {
                    const action = loginPolicyAction(policy)
                    const enabled = platformItemEnabled(policy)
                    const canPatchPolicy = canPatchLoginPolicy(policy.id)
                    const canRemovePolicy = canDeleteLoginPolicy(policy.id)
                    return (
                      <div key={policy.id} className='grid gap-3 p-3 sm:grid-cols-[1fr_auto] sm:items-center'>
                        <div className='min-w-0'>
                          <div className='flex flex-wrap items-center gap-2'>
                            <span className='truncate text-sm font-medium'>{policy.name}</span>
                            <Badge tone={action === 'allow' ? 'success' : 'danger'}>
                              {action === 'allow' ? t('settingsPage.loginPolicyAllow') : t('settingsPage.loginPolicyDeny')}
                            </Badge>
                            <Badge tone={enabled ? 'success' : 'neutral'}>
                              {enabled ? t('settingsPage.loginPolicyEnabled') : t('settingsPage.loginPolicyDisabled')}
                            </Badge>
                          </div>
                          <div className='mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground'>
                            <span>{t('settingsPage.loginPolicyAccount')}: {loginPolicyAccount(policy)}</span>
                            <span>{t('settingsPage.loginPolicyCIDR')}: {loginPolicyCIDR(policy)}</span>
                            <span>{t('settingsPage.loginPolicyPriority')}: {loginPolicyPriority(policy)}</span>
                            <span>{t('settingsPage.loginPolicyExpiresAt')}: {loginPolicyExpiresAt(policy)}</span>
                          </div>
                        </div>
                        {(canPatchPolicy || canRemovePolicy) ? (
                          <div className='flex flex-wrap gap-2 sm:justify-end'>
                            {canPatchPolicy ? (
                              <Button variant='outline' size='sm' onClick={() => void toggleLoginPolicy(policy)} disabled={loginPolicyBusy}>
                                {enabled ? t('settingsPage.disableLoginPolicy') : t('settingsPage.enableLoginPolicy')}
                              </Button>
                            ) : null}
                            {canRemovePolicy ? (
                              <Button variant='destructive' size='sm' onClick={() => void deleteLoginPolicy(policy)} disabled={loginPolicyBusy}>
                                <Trash2 className='size-4' />
                                {t('settingsPage.deleteLoginPolicy')}
                              </Button>
                            ) : null}
                          </div>
                        ) : null}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          ) : null}
          {canReadLoginLocks ? (
          <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div className='flex flex-wrap items-center justify-between gap-2'>
              <div>
                <div className='text-sm font-medium'>{t('settingsPage.loginLocksTitle')}</div>
                <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.loginLocksDescription')}</p>
              </div>
              <Badge tone={loginLocks.length > 0 ? 'danger' : 'neutral'}>
                {t('settingsPage.loginLocksCount', { count: loginLocks.length })}
              </Badge>
            </div>
            {loginLocks.length === 0 ? (
              <div className='rounded-md border border-dashed border-border p-3 text-sm text-muted-foreground'>{t('settingsPage.loginLocksEmpty')}</div>
            ) : (
              <div className='divide-y divide-border overflow-hidden rounded-md border border-border bg-card/60'>
                {loginLocks.map((lock) => (
                  <div key={lock.id} className='grid gap-3 p-3 sm:grid-cols-[1fr_auto] sm:items-center'>
                    <div className='min-w-0'>
                      <div className='flex flex-wrap items-center gap-2'>
                        <span className='truncate text-sm font-medium'>{loginLockAccount(lock)}</span>
                        <Badge tone='danger'>{t('settingsPage.loginLockStatus')}</Badge>
                      </div>
                      <div className='mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground'>
                        <span>{t('settingsPage.loginPolicyCIDR')}: {loginLockClientIP(lock)}</span>
                        <span>{t('settingsPage.loginLockUntil')}: {loginLockUntil(lock)}</span>
                        <span>{t('settingsPage.loginLockFailureCount')}: {loginLockFailureCount(lock)}</span>
                      </div>
                    </div>
                    {canDeleteLoginLock(lock.id) ? (
                      <div className='flex justify-end'>
                        <Button variant='outline' size='sm' onClick={() => void unlockLoginLock(lock)} disabled={loginLockBusy}>
                          {t('settingsPage.unlockLoginLock')}
                        </Button>
                      </div>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </div>
          ) : null}
        </div>
      </CardStaggerItem>
      ) : null}

      {canReadSystemSettings ? (
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
              <Input
                value={ldapSettings.url}
                onChange={(event) => patchLDAP({ url: event.currentTarget.value })}
                placeholder='ldap://directory.example.com:389'
                aria-invalid={ldapURLFieldInvalid}
              />
              {ldapURLFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.ldapUrlInvalid', { defaultValue: 'Enter an ldap:// or ldaps:// URL without credentials, path, query, or fragment.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.ldapBindDN', { defaultValue: 'Bind DN' })}>
              <Input value={ldapSettings.bindDN} onChange={(event) => patchLDAP({ bindDN: event.currentTarget.value })} placeholder='cn=reader,dc=example,dc=com' />
            </Field>
            <Field label={t('password')}>
              <Input type='password' value={ldapSettings.bindPassword} onChange={(event) => patchLDAP({ bindPassword: event.currentTarget.value, bindPasswordClear: false })} placeholder={ldapSettings.bindPasswordSet ? 'Leave blank to keep current password' : ''} autoComplete='new-password' />
            </Field>
            <Field label={t('settingsPage.ldapBaseDN', { defaultValue: 'Base DN' })}>
              <Input value={ldapSettings.baseDN} onChange={(event) => patchLDAP({ baseDN: event.currentTarget.value })} placeholder='ou=people,dc=example,dc=com' aria-invalid={ldapSettings.enabled && !ldapSearchBaseReady} />
            </Field>
            <Field label={t('settingsPage.ldapUserFilter', { defaultValue: 'User filter' })}>
              <Input value={ldapSettings.userFilter} onChange={(event) => patchLDAP({ userFilter: event.currentTarget.value })} placeholder='(uid={username})' />
            </Field>
            <Field label={t('settingsPage.ldapUserDNTemplate', { defaultValue: 'User DN / UPN template' })}>
              <Input value={ldapSettings.userDNTemplate} onChange={(event) => patchLDAP({ userDNTemplate: event.currentTarget.value })} placeholder='uid={username},ou=people,dc=example,dc=com' aria-invalid={ldapSettings.enabled && !ldapSearchBaseReady} />
              {ldapSettings.enabled && !ldapSearchBaseReady ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.ldapSearchBaseRequired', { defaultValue: 'Provide a Base DN for directory search or a user DN/UPN template for direct bind.' })}</span> : null}
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
            <Field label={t('settingsPage.ldapTLSServerName', { defaultValue: 'TLS server name' })}>
              <Input value={ldapSettings.serverName} onChange={(event) => patchLDAP({ serverName: event.currentTarget.value })} placeholder='directory.example.com' />
            </Field>
          </div>
          <div className='grid gap-2 md:grid-cols-2'>
            <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
              <input
                type='checkbox'
                className='size-4 accent-primary'
                checked={ldapSettings.startTLS}
                onChange={(event) => patchLDAP({ startTLS: event.currentTarget.checked })}
              />
              <span>{t('settingsPage.ldapStartTLS', { defaultValue: 'Upgrade ldap:// connections with STARTTLS' })}</span>
            </label>
            <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
              <input
                type='checkbox'
                className='size-4 accent-primary'
                checked={ldapSettings.insecureSkipVerify}
                onChange={(event) => patchLDAP({ insecureSkipVerify: event.currentTarget.checked })}
              />
              <span>{t('settingsPage.ldapInsecureSkipVerify', { defaultValue: 'Skip TLS certificate verification' })}</span>
            </label>
          </div>
          {!ldapTLSModeValid ? <p className='text-xs text-destructive'>{t('settingsPage.ldapTLSModeConflict', { defaultValue: 'STARTTLS cannot be combined with an ldaps:// URL.' })}</p> : null}
          <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
            <input
              type='checkbox'
              className='size-4 accent-primary'
              checked={ldapSettings.autoCreate}
              onChange={(event) => patchLDAP({ autoCreate: event.currentTarget.checked })}
            />
            <span>{t('settingsPage.ldapAutoCreate', { defaultValue: 'Create LDAP users on first successful login' })}</span>
          </label>
          {ldapSettings.bindPasswordSet && (
            <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
              <input
                type='checkbox'
                className='size-4 accent-primary'
                checked={ldapSettings.bindPasswordClear}
                onChange={(event) => patchLDAP({ bindPasswordClear: event.currentTarget.checked, bindPassword: event.currentTarget.checked ? '' : ldapSettings.bindPassword })}
              />
              <span>{t('settingsPage.clearLDAPBindPassword', { defaultValue: 'Clear saved LDAP bind password on save' })}</span>
            </label>
          )}
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
              {canTestLDAPSettings ? (
                <Button
                  variant='outline'
                  onClick={() => void testLDAPSettings()}
                  disabled={ldapTestBusy || !ldapSettings.setting?.id || !ldapTestUsername.trim() || !ldapTestPassword}
                >
                  {ldapTestBusy ? t('testing') : t('settingsPage.testLDAP', { defaultValue: 'Test LDAP' })}
                </Button>
              ) : null}
            </div>
          </div>
          {canSaveLDAPSettings ? (
            <div className='flex justify-end'>
              <Button variant='primary' onClick={() => void saveLDAPSettings()} disabled={ldapBusy || !ldapFormValid}>
                {ldapBusy ? t('saving') : t('save')}
              </Button>
            </div>
          ) : null}
        </div>
      </CardStaggerItem>
      ) : null}

      {canReadSystemSettings ? (
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
                {wecomSettings.agentSecretSet
                  ? t('settingsPage.wecomAgentSecretSaved', { defaultValue: 'Agent secret saved' })
                  : t('settingsPage.wecomAgentSecretNotSet', { defaultValue: 'Agent secret not set' })}
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
              <Input value={wecomSettings.corpID} onChange={(event) => patchWeCom({ corpID: event.currentTarget.value })} placeholder='wwxxxxxxxxxxxxxxxx' maxLength={256} aria-invalid={wecomCorpIDFieldInvalid} />
              {wecomCorpIDFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.wecomCorpIDInvalid', { defaultValue: 'Enter a valid Enterprise WeChat Corp ID without spaces or URL delimiters.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.wecomAgentID', { defaultValue: 'Agent ID' })}>
              <Input value={wecomSettings.agentID} onChange={(event) => patchWeCom({ agentID: event.currentTarget.value })} placeholder='1000002' inputMode='numeric' maxLength={32} aria-invalid={!wecomAgentIDValid} />
              {!wecomAgentIDValid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.wecomAgentIDInvalid', { defaultValue: 'Agent ID must contain only digits.' })}</span> : null}
            </Field>
            <Field label={t('settingsPage.wecomAgentSecret', { defaultValue: 'Agent secret' })}>
              <Input type='password' value={wecomSettings.agentSecret} onChange={(event) => patchWeCom({ agentSecret: event.currentTarget.value, agentSecretClear: false })} placeholder={wecomSettings.agentSecretSet ? t('settingsPage.keepCurrentSecret') : ''} autoComplete='new-password' aria-invalid={wecomAgentSecretFieldInvalid} />
              {wecomAgentSecretFieldInvalid ? <span className='text-xs font-normal text-destructive'>{t('settingsPage.wecomAgentSecretRequired', { defaultValue: 'An Agent secret is required while Enterprise WeChat login is enabled.' })}</span> : null}
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
          {wecomSettings.agentSecretSet && (
            <label className='flex items-center gap-2 rounded-lg border border-border bg-background/70 px-3 py-2 text-sm'>
              <input
                type='checkbox'
                className='size-4 accent-primary'
                checked={wecomSettings.agentSecretClear}
                onChange={(event) => patchWeCom({ agentSecretClear: event.currentTarget.checked, agentSecret: event.currentTarget.checked ? '' : wecomSettings.agentSecret })}
              />
              <span>{t('settingsPage.clearWeComAgentSecret', { defaultValue: 'Clear saved Enterprise WeChat agent secret on save' })}</span>
            </label>
          )}
          <div className='grid gap-3 rounded-lg border border-border bg-background/70 p-3'>
            <div>
              <div className='text-sm font-medium'>{t('settingsPage.wecomTestTitle', { defaultValue: 'Test Enterprise WeChat token' })}</div>
              <p className='mt-1 text-xs leading-5 text-muted-foreground'>{t('settingsPage.wecomTestDescription', { defaultValue: 'Validate the saved Corp ID and agent secret by requesting a WeCom access token. Tokens and secrets are never shown.' })}</p>
            </div>
            <div className='flex justify-end'>
              {canTestWeComSettings ? (
                <Button
                  variant='outline'
                  onClick={() => void testWeComSettings()}
                  disabled={wecomTestBusy || !wecomSettings.setting?.id}
                >
                  {wecomTestBusy ? t('testing') : t('settingsPage.testWeCom', { defaultValue: 'Test WeCom' })}
                </Button>
              ) : null}
            </div>
          </div>
          {canSaveWeComSettings ? (
            <div className='flex justify-end'>
              <Button variant='primary' onClick={() => void saveWeComSettings()} disabled={wecomBusy || !wecomFormValid}>
                {wecomBusy ? t('saving') : t('save')}
              </Button>
            </div>
          ) : null}
        </div>
      </CardStaggerItem>
      ) : null}

      {canReadSystemSettings ? (
      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <History className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.retentionTitle')}</h2>
              <Badge tone={retentionSettings.setting ? 'success' : 'neutral'}>
                {retentionSettings.setting ? t('settingsPage.retentionConfigured') : t('settingsPage.retentionDefault')}
              </Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>{t('settingsPage.retentionDescription')}</p>
            <p className='mt-2 text-xs leading-5 text-muted-foreground'>{t('settingsPage.retentionCleanupHint')}</p>
          </div>
        </div>
        <div className='grid gap-4'>
          <div className='grid gap-3 sm:grid-cols-2'>
            {retentionFieldOptions.map((option) => (
              <Field key={option.key} label={t(option.labelKey)}>
                <Input
                  type='number'
                  min={0}
                  max={36500}
                  step={1}
                  value={retentionSettings[option.key]}
                  onChange={(event) => patchRetentionSettings(option.key, numberInputValue(event.currentTarget.value, 90))}
                />
                <p className='text-xs leading-5 text-muted-foreground'>{t(option.descriptionKey)}</p>
              </Field>
            ))}
          </div>
          {canSaveRetentionSettings ? (
            <div className='flex justify-end'>
              <Button variant='primary' onClick={() => void saveRetentionSettings()} disabled={retentionBusy}>
                {retentionBusy ? t('saving') : t('settingsPage.saveRetention')}
              </Button>
            </div>
          ) : null}
        </div>
      </CardStaggerItem>
      ) : null}

      {canReadLicense ? (
      <CardStaggerItem className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[0.85fr_1.15fr]'>
        <div className='flex min-w-0 items-start gap-3'>
          <span className='grid size-12 shrink-0 place-items-center rounded-full bg-primary text-primary-foreground'>
            <BadgeCheck className='size-5' />
          </span>
          <div className='min-w-0'>
            <div className='flex flex-wrap items-center gap-2'>
              <h2 className='truncate text-base font-semibold'>{t('settingsPage.licenseTitle', { defaultValue: 'Local license' })}</h2>
              <Badge tone={licenseInfo?.status === 'expired' ? 'danger' : 'success'}>
                {licenseInfo?.status || t('loadingConsole')}
              </Badge>
              <Badge tone='neutral'>{licenseInfo?.edition || 'Community'}</Badge>
              <Badge tone='info'>{t('settingsPage.licenseNoEnforcement', { defaultValue: 'No commercial enforcement' })}</Badge>
            </div>
            <p className='mt-1 max-w-lg text-sm leading-6 text-muted-foreground'>
              {t('settingsPage.licenseDescription', { defaultValue: 'Record local license, deployment fingerprint, enabled modules, and resource usage without adding any commercial restriction.' })}
            </p>
          </div>
        </div>
        <div className='grid gap-3'>
          <StaggerContainer className='grid gap-3 md:grid-cols-2'>
            <StaggerItem>
              <InfoTile label={t('version')} value={licenseInfo?.commit ? `${licenseInfo.version} (${licenseInfo.commit})` : licenseInfo?.version || app.publicConfig.version || 'dev'} />
            </StaggerItem>
            <StaggerItem>
              <InfoTile label={t('settingsPage.licenseFingerprint', { defaultValue: 'Installation fingerprint' })} value={licenseInfo?.installation_fingerprint || '-'} />
            </StaggerItem>
            <StaggerItem>
              <InfoTile label={t('settingsPage.licenseRuntime', { defaultValue: 'Runtime' })} value={licenseInfo ? `${licenseInfo.runtime.os || '-'} / ${licenseInfo.runtime.arch || '-'}` : '-'} />
            </StaggerItem>
            <StaggerItem>
              <InfoTile label={t('settingsPage.licenseUsage', { defaultValue: 'Usage' })} value={licenseUsageSummary(licenseInfo)} />
            </StaggerItem>
          </StaggerContainer>
          <div className='rounded-lg border border-border bg-background/70 p-3'>
            <div className='mb-2 text-sm font-medium'>{t('settingsPage.licenseModules', { defaultValue: 'Enabled modules' })}</div>
            <div className='flex flex-wrap gap-2'>
              {(licenseInfo?.modules || []).map((module) => (
                <Badge key={module.key} tone={module.enabled ? 'success' : 'neutral'}>{module.name}</Badge>
              ))}
              {!licenseInfo?.modules?.length ? <span className='text-sm text-muted-foreground'>{t('loadingConsole')}</span> : null}
            </div>
          </div>
          <div className='grid gap-3 md:grid-cols-2'>
            <Field label={t('settingsPage.licensee', { defaultValue: 'Licensee' })}>
              <Input value={licenseForm.licensee} onChange={(event) => patchLicenseForm({ licensee: event.currentTarget.value })} placeholder='Open Web Server Manager' />
            </Field>
            <Field label={t('settingsPage.licenseContact', { defaultValue: 'Contact' })}>
              <Input value={licenseForm.contact} onChange={(event) => patchLicenseForm({ contact: event.currentTarget.value })} placeholder='ops@example.com' />
            </Field>
            <Field label={t('settingsPage.licenseSerial', { defaultValue: 'Serial' })}>
              <Input value={licenseForm.serial} onChange={(event) => patchLicenseForm({ serial: event.currentTarget.value })} placeholder='LOCAL-COMMUNITY' />
            </Field>
            <Field label={t('settingsPage.licenseExpiresAt', { defaultValue: 'Expires at' })}>
              <Input value={licenseForm.expires_at} onChange={(event) => patchLicenseForm({ expires_at: event.currentTarget.value })} placeholder='never or 2027-12-31' />
            </Field>
            <Field label={t('settingsPage.licenseIssuedAt', { defaultValue: 'Issued at' })}>
              <Input value={licenseForm.issued_at} onChange={(event) => patchLicenseForm({ issued_at: event.currentTarget.value })} placeholder='2026-07-06' />
            </Field>
            <Field label={t('settingsPage.licenseFeatures', { defaultValue: 'Feature keys' })}>
              <Input value={licenseForm.features} onChange={(event) => patchLicenseForm({ features: event.currentTarget.value })} placeholder='ssh, rdp, audit, gateway' />
            </Field>
          </div>
          <Field label={t('settingsPage.licenseNotes', { defaultValue: 'Notes' })}>
            <Textarea value={licenseForm.notes} onChange={(event) => patchLicenseForm({ notes: event.currentTarget.value })} placeholder={t('settingsPage.licenseNotesPlaceholder', { defaultValue: 'Local deployment, approval, or procurement notes.' })} />
          </Field>
          {canSaveLicense ? (
            <div className='flex justify-end'>
              <Button variant='primary' onClick={() => void saveLocalLicense()} disabled={licenseBusy}>
                {licenseBusy ? t('saving') : t('save')}
              </Button>
            </div>
          ) : null}
        </div>
      </CardStaggerItem>
      ) : null}
      </>
      ) : null}

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

      <div id='settings-about' className='scroll-mt-20'>
        <AboutContent />
      </div>
      {confirmDialog}
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

function defaultLocalLicenseForm(): LocalLicenseFormState {
  return {
    licensee: '',
    contact: '',
    serial: '',
    issued_at: '',
    expires_at: 'never',
    notes: '',
    features: 'ssh, rdp, vnc, web, database, audit, gateway, identity, backup',
  }
}

function localLicenseFormFromInfo(info: LocalLicenseInfo): LocalLicenseFormState {
  const features = info.features?.length ? info.features : (info.modules || []).filter((module) => module.enabled).map((module) => module.key)
  return {
    licensee: info.licensee || '',
    contact: info.contact || '',
    serial: info.serial || '',
    issued_at: info.issued_at || '',
    expires_at: info.expires_at || 'never',
    notes: info.notes || '',
    features: features.join(', '),
  }
}

function splitLicenseFeatures(value: string) {
  return value.split(/[,;\n]+/).map((item) => item.trim()).filter(Boolean)
}

function licenseUsageSummary(info: LocalLicenseInfo | null) {
  if (!info) return '-'
  const usage = info.usage || {}
  const assets = (usage.assets || 0) + (usage.web_assets || 0) + (usage.database_assets || 0)
  const gateways = (usage.agent_gateways || 0) + (usage.ssh_gateways || 0)
  return `${usage.users || 0} users / ${assets} assets / ${gateways} gateways`
}

function loginSecurityFromSettings(items: PlatformItem[], fallbackCaptcha: boolean, fallbackPasswordDisabled: boolean): LoginSecurityState {
  let captchaEnabled = fallbackCaptcha
  let passwordLoginDisabled = fallbackPasswordDisabled
  let forceMFARequired = false
  let loginFailureThreshold = 5
  let loginFailureWindowMinutes = 15
  let loginLockMinutes = 5
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
    if (forceMFAKeys.some((key) => metadataTruthy(metadata[key]))) {
      forceMFARequired = true
    }
    loginFailureThreshold = metadataNumberByKeys(metadata, loginFailureThresholdKeys, loginFailureThreshold, 1, 50)
    loginFailureWindowMinutes = metadataNumberByKeys(metadata, loginFailureWindowKeys, loginFailureWindowMinutes, 1, 1440)
    loginLockMinutes = metadataNumberByKeys(metadata, loginLockMinutesKeys, loginLockMinutes, 1, 1440)
  }
  const setting =
    candidates.find((item) => item.name === 'Login security') ||
    candidates.find((item) => hasLoginSecurityMetadata(item)) ||
    candidates[0]
  return { captchaEnabled, passwordLoginDisabled, forceMFARequired, loginFailureThreshold, loginFailureWindowMinutes, loginLockMinutes, setting }
}

function defaultRetentionSettings(): RetentionSettingsState {
  return {
    sessionDays: 90,
    loginDays: 90,
    scheduledTaskDays: 90,
    operationDays: 90,
    fileDays: 90,
    accessDays: 90,
    sqlDays: 90,
    execCommandDays: 90,
  }
}

function retentionSettingsFromSettings(items: PlatformItem[]): RetentionSettingsState {
  const setting = items.find((item) => platformItemEnabled(item) && (item.type || '').trim().toLowerCase() === 'retention')
  if (!setting) return defaultRetentionSettings()
  const metadata = setting.metadata ?? {}
  const fallback = metadataNumberByKeys(metadata, ['retention_days', 'days'], 90, 0, 36500)
  return {
    sessionDays: metadataNumberByKeys(metadata, ['connection_sessions_days', 'connection_session_days', 'sessions_days', 'session_days', 'offline_sessions_days', 'offline_session_days', 'recordings_days', 'recording_days'], fallback, 0, 36500),
    loginDays: metadataNumberByKeys(metadata, ['login_logs_days', 'login_days'], fallback, 0, 36500),
    scheduledTaskDays: metadataNumberByKeys(metadata, ['scheduled_task_logs_days', 'scheduled_tasks_days', 'scheduled_task_days', 'operation_logs_days', 'operation_days'], fallback, 0, 36500),
    operationDays: metadataNumberByKeys(metadata, ['operation_logs_days', 'operation_days'], fallback, 0, 36500),
    fileDays: metadataNumberByKeys(metadata, ['file_logs_days', 'file_days'], fallback, 0, 36500),
    accessDays: metadataNumberByKeys(metadata, ['access_logs_days', 'access_days'], fallback, 0, 36500),
    sqlDays: metadataNumberByKeys(metadata, ['sql_logs_days', 'sql_days'], fallback, 0, 36500),
    execCommandDays: metadataNumberByKeys(metadata, ['exec_command_logs_days', 'exec_command_days'], fallback, 0, 36500),
    setting,
  }
}

function defaultOIDCSettings(): OIDCSettingsState {
  return {
    enabled: false,
    providerName: 'OIDC',
    issuer: '',
    authorizationEndpoint: '',
    tokenEndpoint: '',
    userInfoEndpoint: '',
    jwksEndpoint: '',
    clientID: '',
    clientSecret: '',
    clientSecretSet: false,
    clientSecretClear: false,
    tokenAuthMethod: 'client_secret_basic',
    requireIDToken: true,
    scopes: 'openid profile email',
    role: 'user',
    autoCreate: true,
  }
}

function defaultLDAPSettings(): LDAPSettingsState {
  return {
    enabled: false,
    providerName: 'LDAP',
    url: '',
    bindDN: '',
    bindPassword: '',
    bindPasswordSet: false,
    bindPasswordClear: false,
    baseDN: '',
    userFilter: '(uid={username})',
    userDNTemplate: '',
    usernameAttribute: 'uid',
    displayNameAttribute: 'cn',
    emailAttribute: 'mail',
    role: 'user',
    autoCreate: true,
    startTLS: false,
    serverName: '',
    insecureSkipVerify: false,
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
    agentSecretClear: false,
    role: 'user',
    autoCreate: true,
  }
}

function oidcSettingsFromSettings(items: PlatformItem[]): OIDCSettingsState {
  const candidates = items.filter((item) => {
    const type = (item.type || '').trim().toLowerCase()
    return platformItemEnabled(item) && type === 'identity' && hasOIDCMetadata(item)
  })
  const setting = candidates.find((item) => item.name === 'External OIDC identity') || candidates[0]
  if (!setting) return defaultOIDCSettings()
  const metadata = setting.metadata ?? {}
  const userInfoEndpoint = metadataText(metadata.oidc_userinfo_endpoint) || metadataText(metadata.userinfo_endpoint) || metadataText(metadata.user_info_endpoint) || ''
  return {
    enabled: metadataBoolValue(metadata.oidc_login_enabled) === true || metadataBoolValue(metadata.external_oidc_enabled) === true,
    providerName: metadataText(metadata.oidc_provider_name) || metadataText(metadata.provider_name) || setting.name || 'OIDC',
    issuer: metadataText(metadata.oidc_issuer) || metadataText(metadata.issuer) || metadataText(metadata.issuer_url) || '',
    authorizationEndpoint: metadataText(metadata.oidc_authorization_endpoint) || metadataText(metadata.authorization_endpoint) || metadataText(metadata.authorize_endpoint) || '',
    tokenEndpoint: metadataText(metadata.oidc_token_endpoint) || metadataText(metadata.token_endpoint) || '',
    userInfoEndpoint,
    jwksEndpoint: metadataText(metadata.oidc_jwks_uri) || metadataText(metadata.jwks_uri) || metadataText(metadata.jwks_endpoint) || metadataText(metadata.jwks_url) || '',
    clientID: metadataText(metadata.oidc_client_id) || metadataText(metadata.client_id) || '',
    clientSecret: '',
    clientSecretSet: metadataBoolValue(metadata.oidc_client_secret_set) === true,
    clientSecretClear: false,
    tokenAuthMethod: normalizeOIDCTokenAuthMethod(metadataText(metadata.oidc_token_endpoint_auth_method) || metadataText(metadata.token_endpoint_auth_method) || metadataText(metadata.oidc_auth_method)),
    requireIDToken: metadata.oidc_require_id_token === undefined
      ? !userInfoEndpoint
      : metadataBoolValue(metadata.oidc_require_id_token) === true,
    scopes: metadataListText(metadata.oidc_scopes) || metadataText(metadata.scope) || metadataText(metadata.scopes) || 'openid profile email',
    role: metadataText(metadata.oidc_role) || metadataText(metadata.role) || 'user',
    autoCreate: metadata.oidc_auto_create === undefined ? true : metadataBoolValue(metadata.oidc_auto_create) === true,
    setting,
  }
}

function normalizeOIDCTokenAuthMethod(value: string): OIDCSettingsState['tokenAuthMethod'] {
  if (value === 'client_secret_post' || value === 'none') return value
  return 'client_secret_basic'
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
    bindPasswordClear: false,
    baseDN: metadataText(metadata.ldap_base_dn) || metadataText(metadata.base_dn) || '',
    userFilter: metadataText(metadata.ldap_user_filter) || metadataText(metadata.user_filter) || '(uid={username})',
    userDNTemplate: metadataText(metadata.ldap_user_dn_template) || metadataText(metadata.user_dn_template) || '',
    usernameAttribute: metadataText(metadata.ldap_username_attribute) || metadataText(metadata.username_attribute) || 'uid',
    displayNameAttribute: metadataText(metadata.ldap_display_name_attribute) || metadataText(metadata.display_name_attribute) || 'cn',
    emailAttribute: metadataText(metadata.ldap_email_attribute) || metadataText(metadata.email_attribute) || 'mail',
    role: metadataText(metadata.ldap_role) || metadataText(metadata.role) || 'user',
    autoCreate: metadata.ldap_auto_create === undefined ? true : metadataBoolValue(metadata.ldap_auto_create) === true,
    startTLS: metadataBoolValue(metadata.ldap_start_tls) === true || metadataBoolValue(metadata.start_tls) === true,
    serverName: metadataText(metadata.ldap_server_name) || metadataText(metadata.tls_server_name) || metadataText(metadata.server_name) || '',
    insecureSkipVerify: metadataBoolValue(metadata.ldap_insecure_skip_verify) === true || metadataBoolValue(metadata.insecure_skip_verify) === true,
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
    agentSecretClear: false,
    role: metadataText(metadata.wecom_role) || metadataText(metadata.role) || 'user',
    autoCreate: metadata.wecom_auto_create === undefined ? true : metadataBoolValue(metadata.wecom_auto_create) === true,
    setting,
  }
}

function hasOIDCMetadata(item: PlatformItem) {
  const metadata = item.metadata ?? {}
  return oidcSettingKeys.some((key) => Object.prototype.hasOwnProperty.call(metadata, key))
}

function hasLDAPMetadata(item: PlatformItem) {
  const metadata = item.metadata ?? {}
  return ldapSettingKeys.some((key) => Object.prototype.hasOwnProperty.call(metadata, key))
}

function isValidOIDCEndpoint(value: string, allowQuery: boolean) {
  try {
    const parsed = new URL(value.trim())
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false
    if (!parsed.hostname || parsed.username || parsed.password || parsed.hash) return false
    if (!allowQuery && parsed.search) return false
    if (parsed.protocol === 'http:') {
      const host = parsed.hostname.toLowerCase()
      if (host !== 'localhost' && host !== '::1' && host !== '[::1]' && !host.startsWith('127.')) return false
    }
    return true
  } catch {
    return false
  }
}

function isValidLDAPURL(value: string) {
  try {
    const parsed = new URL(value.trim())
    if (parsed.protocol !== 'ldap:' && parsed.protocol !== 'ldaps:') return false
    if (!parsed.hostname || parsed.username || parsed.password || parsed.search || parsed.hash) return false
    if (parsed.pathname && parsed.pathname !== '/') return false
    if (parsed.port) {
      const port = Number(parsed.port)
      if (!Number.isInteger(port) || port < 1 || port > 65535) return false
    }
    return true
  } catch {
    return false
  }
}

function hasWeComMetadata(item: PlatformItem) {
  const metadata = item.metadata ?? {}
  return wecomSettingKeys.some((key) => Object.prototype.hasOwnProperty.call(metadata, key))
}

function hasLoginSecurityMetadata(item: PlatformItem) {
  const metadata = item.metadata ?? {}
  return [
    ...captchaKeys,
    ...disablePasswordKeys,
    ...passwordLoginKeys,
    ...forceMFAKeys,
    ...loginFailureThresholdKeys,
    ...loginFailureWindowKeys,
    ...loginLockMinutesKeys,
  ].some((key) => Object.prototype.hasOwnProperty.call(metadata, key))
}

function platformItemEnabled(item: PlatformItem) {
  const status = (item.status || '').trim().toLowerCase()
  return status === '' || status === 'enabled' || status === 'active' || status === 'locked'
}

function loginPolicyAction(policy: PlatformItem): 'allow' | 'deny' {
  const action = (metadataText(policy.metadata?.action) || policy.type || '').trim().toLowerCase()
  return action === 'allow' ? 'allow' : 'deny'
}

function loginPolicyAccount(policy: PlatformItem) {
  return metadataText(policy.metadata?.account) || metadataText(policy.metadata?.username) || policy.username || '*'
}

function loginPolicyCIDR(policy: PlatformItem) {
  return metadataText(policy.metadata?.cidr) || metadataText(policy.metadata?.client_ip) || policy.host || policy.target_id || '*'
}

function loginPolicyPriority(policy: PlatformItem) {
  const value = policy.metadata?.priority
  return typeof value === 'number' || typeof value === 'string' ? String(value) : '0'
}

function loginPolicyExpiresAt(policy: PlatformItem) {
  const value = metadataText(policy.metadata?.expires_at)
  return value ? formatDate(value) : '-'
}

function loginLockAccount(lock: PlatformItem) {
  return metadataText(lock.metadata?.account) || metadataText(lock.metadata?.username) || lock.username || lock.name || '*'
}

function loginLockClientIP(lock: PlatformItem) {
  return metadataText(lock.metadata?.client_ip) || lock.host || '*'
}

function loginLockUntil(lock: PlatformItem) {
  return metadataText(lock.metadata?.locked_until) || '-'
}

function loginLockFailureCount(lock: PlatformItem) {
  return metadataText(lock.metadata?.failure_count) || '0'
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

function metadataNumberByKeys(metadata: Record<string, unknown>, keys: string[], fallback: number, min: number, max: number) {
  for (const key of keys) {
    const parsed = metadataNumberValue(metadata[key])
    if (parsed !== null) return clampSettingNumber(parsed, min, max, fallback)
  }
  return fallback
}

function metadataNumberValue(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value !== 'string') return null
  const parsed = Number.parseInt(value.trim(), 10)
  return Number.isFinite(parsed) ? parsed : null
}

function numberInputValue(value: string, fallback: number) {
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) ? parsed : fallback
}

function clampSettingNumber(value: number, min: number, max: number, fallback: number) {
  if (!Number.isFinite(value)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(value)))
}

function metadataText(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return ''
}

function metadataListText(value: unknown): string {
  if (Array.isArray(value)) return value.map(metadataText).filter(Boolean).join(' ')
  return metadataText(value)
}
