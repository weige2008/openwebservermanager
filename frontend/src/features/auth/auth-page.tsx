import { useNavigate } from '@tanstack/react-router'
import { Loader2 } from 'lucide-react'
import { useEffect, useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { AuthLayout } from '@/components/layout/auth-layout'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'
import { apiRequest } from '@/lib/api'
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

export function AuthPage() {
  const app = useApp()
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [submitting, setSubmitting] = useState(false)
  const [mfaChallenge, setMFAChallenge] = useState<MFAChallenge | null>(null)
  const [captcha, setCaptcha] = useState<CaptchaChallenge | null>(null)

  const loadCaptcha = async () => {
    setCaptcha(await apiRequest<CaptchaChallenge>('/api/auth/captcha'))
  }

  useEffect(() => {
    if (!app.setupRequired && app.captchaRequired && !mfaChallenge) {
      void loadCaptcha().catch(() => undefined)
    } else {
      setCaptcha(null)
    }
  }, [app.setupRequired, app.captchaRequired, mfaChallenge])

  const finishSignIn = async () => {
    const next = new URLSearchParams(window.location.search).get('next')
    if (next && next.startsWith('/') && !next.startsWith('//')) {
      window.location.assign(next)
      return
    }
    await navigate({ to: '/app' })
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
          window.alert(`Recovery codes:\n\n${result.recovery_codes.join('\n')}`)
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
            <Field label={t('auth.username')}>
              <Input name='username' autoComplete='username' placeholder='admin' defaultValue={app.setupRequired ? 'admin' : ''} required />
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
          {mfaChallenge ? 'Verify MFA' : app.setupRequired ? t('auth.setupSubmit') : t('auth.loginSubmit')}
        </Button>
      </form>
      <p className='text-center text-xs text-muted-foreground'>
        {app.setupRequired ? t('auth.setupSecurityNote') : t('auth.loginSecurityNote')}
      </p>
    </AuthLayout>
  )
}
