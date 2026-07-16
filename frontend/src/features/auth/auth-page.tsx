import { useNavigate } from '@tanstack/react-router'
import { Copy, Fingerprint, Loader2 } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { AuthLayout } from '@/components/layout/auth-layout'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'
import { apiRequest } from '@/lib/api'
import { copyText } from '@/lib/clipboard'
import {
  decodePasskeyRequestOptions,
  passkeyAssertionPayload,
  passkeySecureContext,
  passkeySupported,
  type PasskeyOptionsResponse,
  type PasskeyRequestPublicKeyOptions,
} from '@/lib/passkeys'
import type { AuthUser } from '@/types'

interface LoginResponse {
  user?: AuthUser
  mfa_required?: boolean
  mfa_setup_required?: boolean
  mfa_token?: string
  secret?: string
  otpauth_url?: string
  recovery_codes?: string[]
}

interface MFAChallenge {
  token: string
  setupRequired: boolean
  secret?: string
  otpauthURL?: string
}

interface CaptchaChallenge {
  captcha_id: string
  question: string
  expires_at: string
}

interface OIDCProvider {
  id: string
  name: string
}

interface WeComProvider {
  id: string
  name: string
}

interface PendingRecoveryCodes {
  user: AuthUser
  codes: string[]
}

export function AuthPage() {
  const app = useApp()
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [submitting, setSubmitting] = useState(false)
  const [passkeySubmitting, setPasskeySubmitting] = useState(false)
  const [username, setUsername] = useState(app.setupRequired ? 'admin' : '')
  const [mfaChallenge, setMFAChallenge] = useState<MFAChallenge | null>(null)
  const [captcha, setCaptcha] = useState<CaptchaChallenge | null>(null)
  const [oidcProviders, setOIDCProviders] = useState<OIDCProvider[]>([])
  const [wecomProviders, setWeComProviders] = useState<WeComProvider[]>([])
  const [pendingRecoveryCodes, setPendingRecoveryCodes] = useState<PendingRecoveryCodes | null>(null)
  const passwordFormAvailable = !app.passwordLoginDisabled || app.ldapLoginEnabled
  const canUsePasskey = passkeySupported() && passkeySecureContext()

  const loadCaptcha = async () => {
    setCaptcha(await apiRequest<CaptchaChallenge>('/api/auth/captcha'))
  }

  useEffect(() => {
    if (app.setupRequired && !username) setUsername('admin')
    if (!app.setupRequired && app.captchaRequired && !mfaChallenge) {
      void loadCaptcha().catch(() => undefined)
    } else {
      setCaptcha(null)
    }
  }, [app.setupRequired, app.captchaRequired, mfaChallenge, username])

  useEffect(() => {
    if (app.setupRequired) {
      setOIDCProviders([])
      setWeComProviders([])
      return
    }
    void apiRequest<{ providers: OIDCProvider[] }>('/api/auth/oidc/providers')
      .then((payload) => setOIDCProviders(payload.providers || []))
      .catch(() => setOIDCProviders([]))
    void apiRequest<{ providers: WeComProvider[] }>('/api/auth/wecom/providers')
      .then((payload) => setWeComProviders(payload.providers || []))
      .catch(() => setWeComProviders([]))
  }, [app.setupRequired])

  const finishSignIn = async () => {
    const next = new URLSearchParams(window.location.search).get('next')
    if (next && next.startsWith('/') && !next.startsWith('//')) {
      window.location.assign(next)
      return
    }
    await navigate({ to: '/app' })
  }

  const startOIDCLogin = (provider: OIDCProvider) => {
    const next = new URLSearchParams(window.location.search).get('next') || '/app'
    const params = new URLSearchParams({ provider: provider.id, next })
    window.location.assign(`/api/auth/oidc/start?${params.toString()}`)
  }

  const startWeComLogin = (provider: WeComProvider) => {
    const next = new URLSearchParams(window.location.search).get('next') || '/app'
    const params = new URLSearchParams({ provider: provider.id, next })
    window.location.assign(`/api/auth/wecom/start?${params.toString()}`)
  }

  const continueAfterRecoveryCodes = async () => {
    if (!pendingRecoveryCodes) return
    app.setAuthenticatedUser(pendingRecoveryCodes.user)
    await app.refresh(true)
    app.showToast(t('auth.signedIn'))
    await finishSignIn()
  }

  const copyRecoveryCodes = async () => {
    if (!pendingRecoveryCodes?.codes.length) return
    try {
      await copyText(pendingRecoveryCodes.codes.join('\n'))
      app.showToast(t('auth.recoveryCodesCopied', { defaultValue: 'Recovery codes copied.' }))
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const startPasskeyLogin = async () => {
    const account = username.trim()
    if (!account) {
      app.showToast(t('auth.passkeyUsernameRequired', { defaultValue: 'Enter your username first.' }))
      return
    }
    if (!passkeySupported()) {
      app.showToast(t('auth.passkeyUnsupported', { defaultValue: 'This browser does not support passkeys.' }))
      return
    }
    if (!passkeySecureContext()) {
      app.showToast(t('auth.passkeySecureContextRequired', { defaultValue: 'Passkeys require HTTPS or localhost.' }))
      return
    }
    setPasskeySubmitting(true)
    try {
      const options = await apiRequest<PasskeyOptionsResponse<PasskeyRequestPublicKeyOptions>>('/api/auth/passkeys/login/options', {
        method: 'POST',
        body: JSON.stringify({ username: account }),
      })
      const credential = await navigator.credentials.get({
        publicKey: decodePasskeyRequestOptions(options.publicKey),
      })
      if (!credential) throw new Error(t('operationFailed'))
      const result = await apiRequest<LoginResponse>('/api/auth/passkeys/login/verify', {
        method: 'POST',
        body: JSON.stringify(passkeyAssertionPayload(credential as PublicKeyCredential, options.challenge_id)),
      })
      if (result.mfa_required || result.mfa_setup_required) {
        if (!result.mfa_token) throw new Error(t('operationFailed'))
        setMFAChallenge({
          token: result.mfa_token,
          setupRequired: Boolean(result.mfa_setup_required),
          secret: result.secret,
          otpauthURL: result.otpauth_url,
        })
        return
      }
      if (!result.user) throw new Error(t('operationFailed'))
      app.setAuthenticatedUser(result.user)
      await app.refresh(true)
      app.showToast(t('auth.signedIn'))
      await finishSignIn()
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setPasskeySubmitting(false)
    }
  }

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)

    try {
      if (mfaChallenge) {
        const result = await apiRequest<LoginResponse>('/api/auth/mfa/complete-login', {
          method: 'POST',
          body: JSON.stringify({
            token: mfaChallenge.token,
            mfa_code: String(form.get('mfa_code') || ''),
            recovery_code: String(form.get('recovery_code') || ''),
          }),
        })
        if (!result.user) throw new Error(t('operationFailed'))
        if (result.recovery_codes?.length) {
          setPendingRecoveryCodes({ user: result.user, codes: result.recovery_codes })
          return
        }
        app.setAuthenticatedUser(result.user)
        await app.refresh(true)
        app.showToast(t('auth.signedIn'))
        await finishSignIn()
      } else if (app.setupRequired) {
        const password = String(form.get('password') || '')
        const confirm = String(form.get('confirm_password') || '')
        if (password !== confirm) {
          app.showToast(t('auth.passwordMismatch'))
          return
        }

        const result = await apiRequest<{ user: AuthUser }>('/api/auth/setup', {
          method: 'POST',
          body: JSON.stringify({
            username: String(form.get('username') || 'admin'),
            password,
          }),
        })
        app.setAuthenticatedUser(result.user)
        await app.refresh(true)
        app.showToast(t('auth.adminCreated'))
        await finishSignIn()
      } else {
        const result = await apiRequest<LoginResponse>('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({
            username: String(form.get('username') || ''),
            password: String(form.get('password') || ''),
            captcha_id: captcha?.captcha_id || '',
            captcha_answer: String(form.get('captcha_answer') || ''),
          }),
        })
        if (result.mfa_required || result.mfa_setup_required) {
          if (!result.mfa_token) throw new Error(t('operationFailed'))
          setMFAChallenge({
            token: result.mfa_token,
            setupRequired: Boolean(result.mfa_setup_required),
            secret: result.secret,
            otpauthURL: result.otpauth_url,
          })
          return
        }
        if (!result.user) throw new Error(t('operationFailed'))
        app.setAuthenticatedUser(result.user)
        await app.refresh(true)
        app.showToast(t('auth.signedIn'))
        await finishSignIn()
      }
    } catch (error) {
      app.handleApiError(error)
      if (app.captchaRequired && !mfaChallenge && !app.setupRequired) {
        void loadCaptcha().catch(() => undefined)
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <AuthLayout>
      <div className='space-y-2'>
        <div className='text-xs font-medium tracking-[0.12em] text-muted-foreground uppercase'>{app.setupRequired ? t('auth.firstRun') : t('auth.adminConsole')}</div>
        <h1 className='text-3xl font-semibold tracking-tight'>{app.setupRequired ? t('auth.setupTitle') : t('auth.loginTitle')}</h1>
        <p className='text-sm leading-relaxed text-muted-foreground'>
          {app.setupRequired ? t('auth.setupDescription') : t('auth.loginDescription')}
        </p>
      </div>
      {pendingRecoveryCodes ? (
        <div className='grid gap-4'>
          <div className='rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm leading-6 text-amber-800 dark:text-amber-100'>
            <div className='font-medium'>{t('auth.recoveryCodesTitle', { defaultValue: 'Save your recovery codes' })}</div>
            <p className='mt-1 text-xs leading-5'>{t('auth.recoveryCodesDescription', { defaultValue: 'These codes are shown once. Store them somewhere safe before entering the console.' })}</p>
          </div>
          <div className='grid grid-cols-1 gap-2 sm:grid-cols-2'>
            {pendingRecoveryCodes.codes.map((code) => (
              <code key={code} className='rounded-lg border border-border bg-muted px-3 py-2 text-center font-mono text-sm'>
                {code}
              </code>
            ))}
          </div>
          <div className='grid gap-2 sm:grid-cols-2'>
            <Button type='button' variant='outline' onClick={() => void copyRecoveryCodes()}>
              <Copy className='size-4' />
              {t('auth.copyRecoveryCodes', { defaultValue: 'Copy codes' })}
            </Button>
            <Button type='button' variant='primary' onClick={() => void continueAfterRecoveryCodes()}>
              {t('auth.continueAfterRecoveryCodes', { defaultValue: 'I saved them, continue' })}
            </Button>
          </div>
        </div>
      ) : (
      <form className='grid gap-4' onSubmit={onSubmit}>
        {mfaChallenge ? (
          <>
            {mfaChallenge.setupRequired ? (
              <div className='rounded-lg border border-border bg-muted/40 p-3 text-sm'>
                <div className='font-medium'>Set up MFA</div>
                <p className='mt-1 text-muted-foreground'>Add this TOTP secret to your authenticator app, then enter the current code.</p>
                <div className='mt-2 break-all font-mono text-xs'>{mfaChallenge.secret}</div>
                {mfaChallenge.otpauthURL ? <div className='mt-2 break-all font-mono text-xs text-muted-foreground'>{mfaChallenge.otpauthURL}</div> : null}
              </div>
            ) : null}
            <Field label='MFA code'>
              <Input name='mfa_code' inputMode='numeric' autoComplete='one-time-code' placeholder='123456' />
            </Field>
            {!mfaChallenge.setupRequired ? (
              <Field label='Recovery code'>
                <Input name='recovery_code' autoComplete='one-time-code' placeholder='optional' />
              </Field>
            ) : null}
            <button type='button' className='text-left text-xs text-muted-foreground hover:text-foreground' onClick={() => setMFAChallenge(null)}>
              Back to password login
            </button>
          </>
        ) : (
          <>
            {!app.setupRequired && app.passwordLoginDisabled ? (
              <div className='rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm leading-6 text-amber-700 dark:text-amber-200'>
                {app.ldapLoginEnabled ? t('auth.ldapLoginNotice', { defaultValue: 'Local password login is disabled. Use your LDAP directory account here, or use another SSO provider.' }) : t('auth.passwordLoginDisabledNotice')}
              </div>
            ) : null}
            <Field label={t('auth.username')}>
              <Input name='username' autoComplete='username' placeholder='admin' value={username} onChange={(event) => setUsername(event.currentTarget.value)} required />
            </Field>
            <Field label={app.setupRequired ? t('auth.newPassword') : t('auth.password')}>
              <Input
                name='password'
                type='password'
                autoComplete={app.setupRequired ? 'new-password' : 'current-password'}
                placeholder={app.setupRequired ? t('auth.setupPasswordPlaceholder') : t('auth.loginPasswordPlaceholder')}
                minLength={app.setupRequired ? 8 : undefined}
                required
              />
            </Field>
            {app.setupRequired ? (
              <Field label={t('auth.confirmPassword')}>
                <Input name='confirm_password' type='password' autoComplete='new-password' placeholder={t('auth.setupPasswordPlaceholder')} minLength={8} required />
              </Field>
            ) : null}
            {!app.setupRequired && app.captchaRequired ? (
              <div className='grid gap-2'>
                <div className='grid grid-cols-[minmax(0,1fr)_auto] items-end gap-2'>
                  <Field label='Captcha'>
                    <Input name='captcha_answer' inputMode='numeric' placeholder={captcha?.question || 'Loading...'} required />
                  </Field>
                  <Button type='button' variant='outline' onClick={() => void loadCaptcha()} disabled={submitting}>Refresh</Button>
                </div>
              </div>
            ) : null}
          </>
        )}
        <Button type='submit' variant='primary' className='w-full' disabled={submitting}>
          {submitting ? <Loader2 className='size-4 animate-spin' /> : null}
          {mfaChallenge ? 'Verify MFA' : app.setupRequired ? t('auth.setupSubmit') : passwordFormAvailable ? t('auth.loginSubmit') : t('auth.passwordLoginDisabledSubmit')}
        </Button>
      </form>
      )}
      {!pendingRecoveryCodes && !app.setupRequired && !mfaChallenge ? (
        <div className='grid gap-2'>
          <div className='flex items-center gap-3 text-xs text-muted-foreground'>
            <span className='h-px flex-1 bg-border' />
            <span>{t('auth.passwordless', { defaultValue: 'Passwordless' })}</span>
            <span className='h-px flex-1 bg-border' />
          </div>
          <Button type='button' variant='outline' className='w-full' onClick={() => void startPasskeyLogin()} disabled={passkeySubmitting || submitting || !canUsePasskey}>
            {passkeySubmitting ? <Loader2 className='size-4 animate-spin' /> : <Fingerprint className='size-4' />}
            {canUsePasskey ? t('auth.passkeyLogin', { defaultValue: 'Sign in with passkey' }) : t('auth.passkeyUnavailable', { defaultValue: 'Passkey requires HTTPS or localhost' })}
          </Button>
        </div>
      ) : null}
      {!pendingRecoveryCodes && !app.setupRequired && !mfaChallenge && (oidcProviders.length || wecomProviders.length) ? (
        <div className='grid gap-2'>
          <div className='flex items-center gap-3 text-xs text-muted-foreground'>
            <span className='h-px flex-1 bg-border' />
            <span>SSO</span>
            <span className='h-px flex-1 bg-border' />
          </div>
          {oidcProviders.map((provider) => (
            <Button key={provider.id} type='button' variant='outline' className='w-full' onClick={() => startOIDCLogin(provider)}>
              {provider.name}
            </Button>
          ))}
          {wecomProviders.map((provider) => (
            <Button key={`wecom-${provider.id}`} type='button' variant='outline' className='w-full' onClick={() => startWeComLogin(provider)}>
              {provider.name}
            </Button>
          ))}
        </div>
      ) : null}
      {!pendingRecoveryCodes ? (
        <p className='text-center text-xs text-muted-foreground'>
          {app.setupRequired ? t('auth.setupSecurityNote') : t('auth.loginSecurityNote')}
        </p>
      ) : null}
    </AuthLayout>
  )
}
