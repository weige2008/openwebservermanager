import { ShieldCheck } from 'lucide-react'
import { useCallback, useRef, useState } from 'react'

import { useApp } from '@/app/app-provider'
import { Button } from '@/components/ui/button'
import { DialogShell } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/field'
import { ApiError } from '@/lib/api'

export type RequestAccessMFACode = () => Promise<string>

export function isAccessMFARequiredError(error: unknown) {
  if (!(error instanceof ApiError) || error.status !== 428) return false
  const data = error.data && typeof error.data === 'object' && !Array.isArray(error.data)
    ? error.data as Record<string, unknown>
    : {}
  const scope = typeof data.mfa_scope === 'string' ? data.mfa_scope.trim() : ''
  return data.mfa_required === true && data.mfa_setup_required !== true && (scope === '' || scope === 'access')
}

export function useAccessMFADialog() {
  const app = useApp()
  const resolverRef = useRef<((code: string) => void) | null>(null)
  const [open, setOpen] = useState(false)
  const [code, setCode] = useState('')

  const resolveCode = useCallback((value: string) => {
    const resolver = resolverRef.current
    resolverRef.current = null
    setOpen(false)
    setCode('')
    resolver?.(value.trim())
  }, [])

  const requestAccessMFACode = useCallback<RequestAccessMFACode>(() => {
    if (resolverRef.current) resolverRef.current('')
    return new Promise((resolve) => {
      resolverRef.current = resolve
      setCode('')
      setOpen(true)
    })
  }, [])

  const accessMFADialog = (
    <DialogShell
      open={open}
      onOpenChange={(nextOpen) => {
        if (!nextOpen) resolveCode('')
      }}
      compact
      title={app.t('accessMFATitle', 'Access MFA verification')}
      description={app.t('accessMFADescription', 'Enter a current authenticator code or a recovery code before opening the asset session.')}
    >
      <form
        className='grid gap-4'
        onSubmit={(event) => {
          event.preventDefault()
          if (!code.trim()) return
          resolveCode(code)
        }}
      >
        <Field label={app.t('accessMFACodeLabel', 'MFA code')}>
          <Input
            autoFocus
            autoComplete='one-time-code'
            inputMode='text'
            value={code}
            onChange={(event) => setCode(event.currentTarget.value)}
            placeholder={app.t('accessMFACodePlaceholder', '123456 or recovery code')}
          />
        </Field>
        <div className='flex justify-end gap-2'>
          <Button type='button' variant='outline' onClick={() => resolveCode('')}>
            {app.t('cancel', 'Cancel')}
          </Button>
          <Button type='submit' variant='primary' disabled={!code.trim()}>
            <ShieldCheck className='size-4' />
            {app.t('verify', 'Verify')}
          </Button>
        </div>
      </form>
    </DialogShell>
  )

  return { requestAccessMFACode, accessMFADialog }
}
