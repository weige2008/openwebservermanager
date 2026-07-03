import { useNavigate } from '@tanstack/react-router'
import { Loader2 } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { AuthLayout } from '@/components/layout/auth-layout'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'
import { apiRequest } from '@/lib/api'
import type { AuthUser } from '@/types'

export function AuthPage() {
  const app = useApp()
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [submitting, setSubmitting] = useState(false)

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)

    try {
      if (app.setupRequired) {
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
        await navigate({ to: '/app' })
      } else {
        const result = await apiRequest<{ user: AuthUser }>('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({
            username: String(form.get('username') || ''),
            password: String(form.get('password') || ''),
          }),
        })
        app.setAuthenticatedUser(result.user)
        await app.refresh(true)
        app.showToast(t('auth.signedIn'))
        await navigate({ to: '/app' })
      }
    } catch (error) {
      app.handleApiError(error)
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
        <Button type='submit' variant='primary' className='w-full' disabled={submitting}>
          {submitting ? <Loader2 className='size-4 animate-spin' /> : null}
          {app.setupRequired ? t('auth.setupSubmit') : t('auth.loginSubmit')}
        </Button>
      </form>
      <p className='text-center text-xs text-muted-foreground'>
        {app.setupRequired ? t('auth.setupSecurityNote') : t('auth.loginSecurityNote')}
      </p>
    </AuthLayout>
  )
}
