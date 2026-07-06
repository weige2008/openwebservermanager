import { useCallback, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { Button } from './button'
import { DialogShell } from './dialog'

interface ConfirmOptions {
  title: string
  description?: string
  confirmText?: string
  cancelText?: string
  destructive?: boolean
}

export function useConfirmDialog() {
  const { t } = useTranslation()
  const resolverRef = useRef<((confirmed: boolean) => void) | null>(null)
  const [options, setOptions] = useState<ConfirmOptions | null>(null)

  const resolve = useCallback((confirmed: boolean) => {
    const resolver = resolverRef.current
    resolverRef.current = null
    setOptions(null)
    resolver?.(confirmed)
  }, [])

  const confirm = useCallback((nextOptions: ConfirmOptions) => {
    if (resolverRef.current) resolverRef.current(false)
    setOptions(nextOptions)
    return new Promise<boolean>((resolver) => {
      resolverRef.current = resolver
    })
  }, [])

  const confirmDialog = (
    <DialogShell
      open={Boolean(options)}
      onOpenChange={(open) => {
        if (!open) resolve(false)
      }}
      compact
      title={options?.title || ''}
      description={options?.description}
    >
      <div className='flex justify-end gap-2'>
        <Button type='button' variant='outline' onClick={() => resolve(false)}>
          {options?.cancelText || t('cancel', 'Cancel')}
        </Button>
        <Button type='button' variant={options?.destructive ? 'destructive' : 'primary'} onClick={() => resolve(true)}>
          {options?.confirmText || t('confirm', 'Confirm')}
        </Button>
      </div>
    </DialogShell>
  )

  return { confirm, confirmDialog }
}
