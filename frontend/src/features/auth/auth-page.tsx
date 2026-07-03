import { useNavigate } from '@tanstack/react-router'
import { Loader2 } from 'lucide-react'
import { useState, type FormEvent } from 'react'

import { useApp } from '@/app/app-provider'
import { apiRequest } from '@/lib/api'
import type { AuthUser } from '@/types'

import { AuthLayout } from '@/components/layout/auth-layout'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/field'

export function AuthPage() {
  const app = useApp()
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
          app.showToast('两次输入的密码不一致')
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
        app.showToast('管理员已创建')
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
        app.showToast('已登录')
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
        <div className='text-xs font-medium tracking-[0.12em] text-muted-foreground uppercase'>{app.setupRequired ? 'First Run' : 'Admin Console'}</div>
        <h1 className='text-3xl font-semibold tracking-tight'>{app.setupRequired ? '首次设置管理员' : '登录'}</h1>
        <p className='text-sm leading-relaxed text-muted-foreground'>
          {app.setupRequired ? '当前数据库还没有管理员账号。创建后才能查看服务器、凭据、会话与审计数据。' : '登录后查看服务器列表、凭据、连接会话与审计记录。'}
        </p>
      </div>
      <form className='grid gap-4' onSubmit={onSubmit}>
        <Field label='用户名'>
          <Input name='username' autoComplete='username' placeholder='admin' defaultValue={app.setupRequired ? 'admin' : ''} required />
        </Field>
        <Field label={app.setupRequired ? '新密码' : '密码'}>
          <Input
            name='password'
            type='password'
            autoComplete={app.setupRequired ? 'new-password' : 'current-password'}
            placeholder={app.setupRequired ? '至少 8 位' : '请输入管理员密码'}
            minLength={app.setupRequired ? 8 : undefined}
            required
          />
        </Field>
        {app.setupRequired ? (
          <Field label='确认密码'>
            <Input name='confirm_password' type='password' autoComplete='new-password' placeholder='再次输入新密码' minLength={8} required />
          </Field>
        ) : null}
        <Button variant='primary' className='w-full' disabled={submitting}>
          {submitting ? <Loader2 className='size-4 animate-spin' /> : null}
          {app.setupRequired ? '创建管理员并进入控制台' : '登录控制台'}
        </Button>
      </form>
      <p className='text-center text-xs text-muted-foreground'>
        {app.setupRequired ? '密码只会以 bcrypt 哈希形式写入服务端数据库，不会以明文保存。' : '管理员密码保存在服务端数据库中，浏览器只保存 HttpOnly 会话 Cookie。'}
      </p>
    </AuthLayout>
  )
}
