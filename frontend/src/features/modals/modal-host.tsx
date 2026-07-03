import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DialogShell } from '@/components/ui/dialog'
import { EmptyState } from '@/components/ui/empty-state'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { apiRequest } from '@/lib/api'
import type { ConnectionSession, Credential, ManagedServer, Protocol } from '@/types'

export function ModalHost() {
  const app = useApp()
  if (!app.modal) return null

  if (app.modal.type === 'server') return <ServerDialog />
  if (app.modal.type === 'credential') return <CredentialDialog />
  return <ConnectDialog protocol={app.modal.protocol} serverId={app.modal.serverId} />
}

function ServerDialog() {
  const app = useApp()
  const { t } = useTranslation()
  const [submitting, setSubmitting] = useState(false)

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)
    try {
      await apiRequest<ManagedServer>('/api/servers', {
        method: 'POST',
        body: JSON.stringify({
          name: String(form.get('name') || ''),
          host: String(form.get('host') || ''),
          os: String(form.get('os') || 'linux'),
          group: String(form.get('group') || ''),
          ssh_port: Number(form.get('ssh_port') || 22),
          rdp_port: Number(form.get('rdp_port') || 3389),
          description: String(form.get('description') || ''),
        }),
      })
      app.setModal(null)
      await app.refresh(true)
      app.showToast(t('modals.serverAdded'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && app.setModal(null)} title={t('modals.addServerTitle')} description={t('modals.addServerDescription')}>
      <form className='grid grid-cols-1 gap-3 md:grid-cols-2' onSubmit={onSubmit}>
        <Field label={t('name')}><Input name='name' placeholder={t('modals.serverNamePlaceholder')} required /></Field>
        <Field label={t('modals.host')}><Input name='host' placeholder={t('modals.hostPlaceholder')} required /></Field>
        <Field label={t('os')}><Select name='os' defaultValue='linux'><option value='linux'>Linux</option><option value='windows'>Windows</option></Select></Field>
        <Field label={t('group')}><Input name='group' placeholder='default' /></Field>
        <Field label={t('modals.sshPort')}><Input name='ssh_port' type='number' defaultValue={22} /></Field>
        <Field label={t('modals.rdpPort')}><Input name='rdp_port' type='number' defaultValue={3389} /></Field>
        <Field label={t('modals.description')} className='md:col-span-2'><Textarea name='description' placeholder={t('modals.descriptionPlaceholder')} /></Field>
        <div className='flex justify-end gap-2 md:col-span-2'>
          <Button type='button' variant='outline' onClick={() => app.setModal(null)}>{t('cancel')}</Button>
          <Button type='submit' variant='primary' disabled={submitting}>{t('modals.saveServer')}</Button>
        </div>
      </form>
    </DialogShell>
  )
}

function CredentialDialog() {
  const app = useApp()
  const { t } = useTranslation()
  const [submitting, setSubmitting] = useState(false)

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)
    try {
      await apiRequest<Credential>('/api/credentials', {
        method: 'POST',
        body: JSON.stringify({
          name: String(form.get('name') || ''),
          type: String(form.get('type') || ''),
          username: String(form.get('username') || ''),
          domain: String(form.get('domain') || ''),
          password: String(form.get('password') || ''),
          private_key: String(form.get('private_key') || ''),
          passphrase: String(form.get('passphrase') || ''),
        }),
      })
      app.setModal(null)
      await app.refresh(true)
      app.showToast(t('modals.credentialAdded'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && app.setModal(null)} title={t('modals.addCredentialTitle')} description={t('modals.addCredentialDescription')}>
      <form className='grid grid-cols-1 gap-3 md:grid-cols-2' onSubmit={onSubmit}>
        <Field label={t('name')}><Input name='name' placeholder={t('modals.credentialNamePlaceholder')} required /></Field>
        <Field label={t('type')}>
          <Select name='type' defaultValue='ssh_password'>
            <option value='ssh_password'>{t('credentialTypes.ssh_password')}</option>
            <option value='ssh_key'>{t('credentialTypes.ssh_key')}</option>
            <option value='rdp_password'>{t('credentialTypes.rdp_password')}</option>
          </Select>
        </Field>
        <Field label={t('username')}><Input name='username' placeholder='root / ubuntu / Administrator' required /></Field>
        <Field label={t('domainWorkgroup')}><Input name='domain' placeholder={t('optional')} /></Field>
        <Field label={t('modals.password')}><Input name='password' type='password' placeholder={t('optional')} /></Field>
        <Field label={t('modals.privateKeyPassphrase')}><Input name='passphrase' type='password' placeholder={t('optional')} /></Field>
        <Field label={t('modals.privateKey')} className='md:col-span-2'><Textarea name='private_key' placeholder={t('modals.privateKeyPlaceholder')} /></Field>
        <div className='flex justify-end gap-2 md:col-span-2'>
          <Button type='button' variant='outline' onClick={() => app.setModal(null)}>{t('cancel')}</Button>
          <Button type='submit' variant='primary' disabled={submitting}>{t('modals.saveCredential')}</Button>
        </div>
      </form>
    </DialogShell>
  )
}

function ConnectDialog({ protocol, serverId }: { protocol: Protocol; serverId: string }) {
  const app = useApp()
  const { t } = useTranslation()
  const [submitting, setSubmitting] = useState(false)
  const server = app.data.servers.find((item) => item.id === serverId)
  const credentials = app.data.credentials.filter((credential) =>
    protocol === 'ssh'
      ? credential.type === 'ssh_password' || credential.type === 'ssh_key'
      : credential.type === 'rdp_password'
  )

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const credentialId = String(form.get('credential_id') || '')
    setSubmitting(true)
    try {
      if (protocol === 'ssh') {
        const session = await apiRequest<ConnectionSession>('/api/connections/ssh', {
          method: 'POST',
          body: JSON.stringify({ server_id: serverId, credential_id: credentialId, cols: 120, rows: 32, term: 'xterm-256color' }),
        })
        app.setModal(null)
        app.setWorkspace({ type: 'ssh', session, status: 'connecting' })
      } else {
        const session = await apiRequest<ConnectionSession>('/api/connections/rdp', {
          method: 'POST',
          body: JSON.stringify({
            server_id: serverId,
            credential_id: credentialId,
            width: Math.max(1024, window.innerWidth),
            height: Math.max(680, window.innerHeight - 52),
            dpi: 96,
            recording_enabled: form.get('recording_enabled') === 'on',
          }),
        })
        app.setModal(null)
        app.setWorkspace({ type: 'rdp', session, status: 'connecting' })
      }
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }

  const title = t('modals.connectTitle', { name: server?.name || t('modals.connectFallbackServer') })
  const description = t('modals.connectDescription', { protocol: protocol.toUpperCase() })

  return (
    <DialogShell compact open onOpenChange={(open) => !open && app.setModal(null)} title={title} description={description}>
      {credentials.length ? (
        <form className='grid gap-4' onSubmit={onSubmit}>
          <Field label={t('modals.credential')}>
            <Select name='credential_id'>
              {credentials.map((credential) => <option key={credential.id} value={credential.id}>{credential.name} ({credential.username})</option>)}
            </Select>
          </Field>
          <div className='flex flex-wrap gap-2'>
            <Badge>{server?.host || '-'}</Badge>
            <Badge>{protocol === 'ssh' ? `SSH ${server?.ssh_port || 22}` : `RDP ${server?.rdp_port || 3389}`}</Badge>
            <Badge>{protocol === 'rdp' ? t('modals.recordingDisabled') : t('modals.ptyTerminal')}</Badge>
          </div>
          {protocol === 'rdp' ? (
            <label className='flex items-start gap-2 rounded-lg border border-border bg-muted/30 p-3 text-sm'>
              <input name='recording_enabled' type='checkbox' className='mt-1 size-4 accent-current' />
              <span className='grid gap-0.5'>
                <span className='font-medium'>{t('modals.recordingOption')}</span>
                <span className='text-xs text-muted-foreground'>{t('modals.recordingDisabled')}</span>
              </span>
            </label>
          ) : null}
          <div className='flex justify-end gap-2'>
            <Button type='button' variant='outline' onClick={() => app.setModal(null)}>{t('cancel')}</Button>
            <Button type='submit' variant='primary' disabled={submitting}>{t('modals.startConnection')}</Button>
          </div>
        </form>
      ) : (
        <div className='grid gap-4'>
          <EmptyState title={t('modals.noCredentialTitle', { protocol: protocol.toUpperCase() })} body={t('modals.noCredentialBody')} />
          <div className='flex justify-end'>
            <Button variant='primary' onClick={() => app.setModal({ type: 'credential' })}>{t('addCredential')}</Button>
          </div>
        </div>
      )}
    </DialogShell>
  )
}
