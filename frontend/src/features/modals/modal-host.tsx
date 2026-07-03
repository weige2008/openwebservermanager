import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DialogShell } from '@/components/ui/dialog'
import { EmptyState } from '@/components/ui/empty-state'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { apiRequest } from '@/lib/api'
import { credentialsForServer, formatDate, serverSupportsProtocol } from '@/lib/utils'
import type { ConnectionSession, Credential, CredentialType, Locale, ManagedServer, Protocol, ServerOS, Theme, ThemeContentLayout, ThemeSidebarStyle } from '@/types'

export function ModalHost() {
  const app = useApp()
  if (!app.modal) return null

  if (app.modal.type === 'server') return <ServerDialog />
  if (app.modal.type === 'credential') return <CredentialDialog />
  if (app.modal.type === 'profile') return <ProfileDialog />
  if (app.modal.type === 'settings') return <SettingsDialog />
  return <ConnectDialog protocol={app.modal.protocol} serverId={app.modal.serverId} />
}

function ProfileDialog() {
  const app = useApp()
  const { t } = useTranslation()
  const activeSessions = app.data.sessions.filter((session) => session.status === 'active').length

  return (
    <DialogShell compact open onOpenChange={(open) => !open && app.setModal(null)} title={t('profileDialog.title')} description={t('profileDialog.description')}>
      <div className='grid gap-3'>
        <div className='flex items-center gap-3 rounded-xl border border-border bg-muted/30 p-3'>
          <span className='grid size-10 shrink-0 place-items-center rounded-full bg-primary text-sm font-semibold text-primary-foreground'>
            {(app.auth?.username || 'admin').slice(0, 2).toUpperCase()}
          </span>
          <div className='min-w-0'>
            <div className='truncate font-medium'>{app.auth?.username || 'admin'}</div>
            <div className='truncate text-xs text-muted-foreground'>{app.auth?.role || 'admin'}</div>
          </div>
        </div>
        <div className='grid gap-2 sm:grid-cols-2'>
          <InfoTile label={t('profileDialog.userId')} value={app.auth?.id || '-'} />
          <InfoTile label={t('profileDialog.sessionExpires')} value={formatDate(app.auth?.expires_at)} />
          <InfoTile label={t('servers')} value={String(app.data.servers.length)} />
          <InfoTile label={t('credentials')} value={String(app.data.credentials.length)} />
          <InfoTile label={t('profileDialog.activeSessions')} value={String(activeSessions)} />
          <InfoTile label={t('gateway')} value={app.data.guacd?.address || t('guacdOffline')} />
        </div>
      </div>
    </DialogShell>
  )
}

function SettingsDialog() {
  const app = useApp()
  const { t } = useTranslation()

  return (
    <DialogShell open onOpenChange={(open) => !open && app.setModal(null)} title={t('settingsDialog.title')} description={t('settingsDialog.description')}>
      <div className='grid gap-4 md:grid-cols-2'>
        <Field label={t('theme')}>
          <Select value={app.theme} onChange={(event) => app.setTheme(event.currentTarget.value as Theme)}>
            <option value='system'>{t('system')}</option>
            <option value='light'>{t('light')}</option>
            <option value='dark'>{t('dark')}</option>
          </Select>
        </Field>
        <Field label={t('language')}>
          <Select value={app.locale} onChange={(event) => app.setLocale(event.currentTarget.value as Locale)}>
            <option value='zh'>简体中文</option>
            <option value='en'>English</option>
            <option value='zh-TW'>繁體中文</option>
            <option value='fr'>Français</option>
            <option value='ru'>Русский</option>
            <option value='ja'>日本語</option>
            <option value='vi'>Tiếng Việt</option>
          </Select>
        </Field>
        <Field label={t('contentWidth')}>
          <Select value={app.appearance.contentLayout} onChange={(event) => app.setAppearance({ contentLayout: event.currentTarget.value as ThemeContentLayout })}>
            <option value='full'>{t('fullWidth')}</option>
            <option value='centered'>{t('centered')}</option>
          </Select>
        </Field>
        <Field label={t('sidebarStyle')}>
          <Select value={app.appearance.sidebarStyle} onChange={(event) => app.setAppearance({ sidebarStyle: event.currentTarget.value as ThemeSidebarStyle })}>
            <option value='default'>{t('default')}</option>
            <option value='inset'>{t('inset')}</option>
            <option value='floating'>{t('floating')}</option>
          </Select>
        </Field>
        <div className='grid gap-2 rounded-xl border border-border bg-muted/30 p-3 md:col-span-2'>
          <div className='text-sm font-medium'>{t('settingsDialog.systemState')}</div>
          <div className='grid gap-2 sm:grid-cols-3'>
            <InfoTile label={t('gateway')} value={app.data.guacd?.address || t('guacdOffline')} />
            <InfoTile label={t('settingsDialog.resolvedTheme')} value={app.resolvedTheme} />
            <InfoTile label={t('settingsDialog.activeLocale')} value={app.locale} />
          </div>
        </div>
        <div className='flex justify-end gap-2 md:col-span-2'>
          <Button type='button' variant='outline' onClick={app.resetAppearance}>{t('reset')}</Button>
          <Button type='button' variant='primary' onClick={() => app.setModal(null)}>{t('close')}</Button>
        </div>
      </div>
    </DialogShell>
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

function ServerDialog() {
  const app = useApp()
  const { t } = useTranslation()
  const [submitting, setSubmitting] = useState(false)
  const [os, setOS] = useState<ServerOS>('linux')
  const [credentialType, setCredentialType] = useState<CredentialType>('ssh_password')

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)
    try {
      const credentialName = String(form.get('credential_name') || '').trim()
      const username = String(form.get('username') || '').trim()
      const domain = String(form.get('domain') || '').trim()
      const password = String(form.get('password') || '')
      const privateKey = String(form.get('private_key') || '').trim()
      const passphrase = String(form.get('passphrase') || '')
      const hasCredential = Boolean(credentialName || username || domain || password || privateKey || passphrase)

      if (hasCredential && !username) throw new Error(t('modals.credentialUsernameRequired'))
      if (hasCredential && credentialType === 'ssh_key' && !privateKey) throw new Error(t('modals.privateKeyRequired'))
      if (hasCredential && credentialType !== 'ssh_key' && !password) throw new Error(t('modals.passwordRequired'))

      const server = await apiRequest<ManagedServer>('/api/servers', {
        method: 'POST',
        body: JSON.stringify({
          name: String(form.get('name') || ''),
          host: String(form.get('host') || ''),
          os,
          group: String(form.get('group') || ''),
          ssh_port: Number(form.get('ssh_port') || 22),
          rdp_port: Number(form.get('rdp_port') || 3389),
          description: String(form.get('description') || ''),
        }),
      })
      if (hasCredential) {
        await apiRequest<Credential>('/api/credentials', {
          method: 'POST',
          body: JSON.stringify({
            server_id: server.id,
            name: credentialName || `${server.name} ${credentialType === 'rdp_password' ? 'RDP' : 'SSH'}`,
            type: credentialType,
            username,
            domain,
            password,
            private_key: privateKey,
            passphrase,
          }),
        })
      }
      app.setModal(null)
      await app.refresh(true)
      app.showToast(hasCredential ? t('modals.serverAndCredentialAdded') : t('modals.serverAdded'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }

  const onOSChange = (nextOS: ServerOS) => {
    setOS(nextOS)
    setCredentialType(nextOS === 'windows' ? 'rdp_password' : 'ssh_password')
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && app.setModal(null)} title={t('modals.addServerTitle')} description={t('modals.addServerDescription')}>
      <form className='grid grid-cols-1 gap-3 md:grid-cols-2' onSubmit={onSubmit}>
        <Field label={t('name')}><Input name='name' placeholder={t('modals.serverNamePlaceholder')} required /></Field>
        <Field label={t('modals.host')}><Input name='host' placeholder={t('modals.hostPlaceholder')} required /></Field>
        <Field label={t('os')}>
          <Select name='os' value={os} onChange={(event) => onOSChange(event.currentTarget.value as ServerOS)}>
            <option value='linux'>Linux</option>
            <option value='windows'>Windows</option>
          </Select>
        </Field>
        <Field label={t('group')}><Input name='group' placeholder='default' /></Field>
        {os === 'linux' ? (
          <Field label={t('modals.sshPort')}><Input name='ssh_port' type='number' defaultValue={22} /></Field>
        ) : (
          <Field label={t('modals.rdpPort')}><Input name='rdp_port' type='number' defaultValue={3389} /></Field>
        )}
        <Field label={t('modals.description')} className='md:col-span-2'><Textarea name='description' placeholder={t('modals.descriptionPlaceholder')} /></Field>

        <div className='grid gap-3 rounded-xl border border-border bg-muted/25 p-3 md:col-span-2'>
          <div className='flex flex-wrap items-center justify-between gap-2'>
            <div>
              <div className='text-sm font-medium'>{t('modals.defaultCredential')}</div>
              <p className='mt-0.5 text-xs text-muted-foreground'>{t('modals.defaultCredentialDescription')}</p>
            </div>
            <Badge tone={os === 'windows' ? 'info' : 'neutral'}>{os === 'windows' ? 'RDP' : 'SSH'}</Badge>
          </div>
          <div className='grid grid-cols-1 gap-3 md:grid-cols-2'>
            <Field label={t('name')}><Input name='credential_name' placeholder={t('modals.credentialNamePlaceholder')} /></Field>
            <Field label={t('type')}>
              <Select value={credentialType} onChange={(event) => setCredentialType(event.currentTarget.value as CredentialType)}>
                {os === 'windows' ? (
                  <option value='rdp_password'>{t('credentialTypes.rdp_password')}</option>
                ) : (
                  <>
                    <option value='ssh_password'>{t('credentialTypes.ssh_password')}</option>
                    <option value='ssh_key'>{t('credentialTypes.ssh_key')}</option>
                  </>
                )}
              </Select>
            </Field>
            <Field label={t('username')}><Input name='username' placeholder='root / ubuntu / Administrator' /></Field>
            <Field label={t('domainWorkgroup')}><Input name='domain' placeholder={t('optional')} /></Field>
            {credentialType === 'ssh_key' ? (
              <>
                <Field label={t('modals.privateKeyPassphrase')}><Input name='passphrase' type='password' placeholder={t('optional')} /></Field>
                <Field label={t('modals.privateKey')} className='md:col-span-2'><Textarea name='private_key' placeholder={t('modals.privateKeyPlaceholder')} /></Field>
              </>
            ) : (
              <Field label={t('modals.password')}><Input name='password' type='password' placeholder={t('optional')} /></Field>
            )}
          </div>
        </div>
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
  const modal = app.modal?.type === 'credential' ? app.modal : null
  const server = modal?.serverId ? app.data.servers.find((item) => item.id === modal.serverId) : undefined
  const [credentialType, setCredentialType] = useState<CredentialType>(server?.os === 'windows' ? 'rdp_password' : 'ssh_password')

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)
    try {
      const password = String(form.get('password') || '')
      const privateKey = String(form.get('private_key') || '').trim()
      if (credentialType === 'ssh_key' && !privateKey) throw new Error(t('modals.privateKeyRequired'))
      if (credentialType !== 'ssh_key' && !password) throw new Error(t('modals.passwordRequired'))

      await apiRequest<Credential>('/api/credentials', {
        method: 'POST',
        body: JSON.stringify({
          server_id: server?.id || '',
          name: String(form.get('name') || ''),
          type: credentialType,
          username: String(form.get('username') || ''),
          domain: String(form.get('domain') || ''),
          password,
          private_key: privateKey,
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

  const title = server ? t('modals.addServerCredentialTitle', { name: server.name }) : t('modals.addCredentialTitle')
  const description = server ? t('modals.addServerCredentialDescription') : t('modals.addCredentialDescription')

  return (
    <DialogShell open onOpenChange={(open) => !open && app.setModal(null)} title={title} description={description}>
      <form className='grid grid-cols-1 gap-3 md:grid-cols-2' onSubmit={onSubmit}>
        {server ? (
          <div className='flex flex-wrap gap-2 rounded-xl border border-border bg-muted/30 p-3 md:col-span-2'>
            <Badge>{server.name}</Badge>
            <Badge>{server.host}</Badge>
            <Badge tone={server.os === 'windows' ? 'info' : 'neutral'}>{server.os === 'windows' ? 'RDP' : 'SSH'}</Badge>
          </div>
        ) : null}
        <Field label={t('name')}><Input name='name' placeholder={t('modals.credentialNamePlaceholder')} required /></Field>
        <Field label={t('type')}>
          <Select value={credentialType} onChange={(event) => setCredentialType(event.currentTarget.value as CredentialType)}>
            {server?.os === 'windows' ? (
              <option value='rdp_password'>{t('credentialTypes.rdp_password')}</option>
            ) : server?.os === 'linux' ? (
              <>
                <option value='ssh_password'>{t('credentialTypes.ssh_password')}</option>
                <option value='ssh_key'>{t('credentialTypes.ssh_key')}</option>
              </>
            ) : (
              <>
                <option value='ssh_password'>{t('credentialTypes.ssh_password')}</option>
                <option value='ssh_key'>{t('credentialTypes.ssh_key')}</option>
                <option value='rdp_password'>{t('credentialTypes.rdp_password')}</option>
              </>
            )}
          </Select>
        </Field>
        <Field label={t('username')}><Input name='username' placeholder='root / ubuntu / Administrator' required /></Field>
        <Field label={t('domainWorkgroup')}><Input name='domain' placeholder={t('optional')} /></Field>
        <Field label={t('modals.password')}><Input name='password' type='password' placeholder={t('optional')} /></Field>
        {credentialType === 'ssh_key' ? (
          <>
            <Field label={t('modals.privateKeyPassphrase')}><Input name='passphrase' type='password' placeholder={t('optional')} /></Field>
            <Field label={t('modals.privateKey')} className='md:col-span-2'><Textarea name='private_key' placeholder={t('modals.privateKeyPlaceholder')} /></Field>
          </>
        ) : null}
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
  const credentials = credentialsForServer(app.data.credentials, server).filter((credential) =>
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

  if (!serverSupportsProtocol(server, protocol)) {
    return (
      <DialogShell compact open onOpenChange={(open) => !open && app.setModal(null)} title={title} description={description}>
        <EmptyState title={t('modals.protocolUnavailableTitle')} body={t('modals.protocolUnavailableBody')} />
      </DialogShell>
    )
  }

  return (
    <DialogShell compact open onOpenChange={(open) => !open && app.setModal(null)} title={title} description={description}>
      {credentials.length ? (
        <form className='grid gap-4' onSubmit={onSubmit}>
          <Field label={t('modals.credential')}>
            <Select name='credential_id'>
              {credentials.map((credential) => (
                <option key={credential.id} value={credential.id}>
                  {credential.name} ({credential.username}){credential.server_id ? '' : ` - ${t('modals.sharedCredential')}`}
                </option>
              ))}
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
            <Button variant='primary' onClick={() => app.setModal({ type: 'credential', serverId })}>{t('addCredential')}</Button>
          </div>
        </div>
      )}
    </DialogShell>
  )
}
