import { useState, type FormEvent } from 'react'

import { useApp } from '@/app/app-provider'
import { apiRequest } from '@/lib/api'
import type { ConnectionSession, Credential, ManagedServer, Protocol } from '@/types'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DialogShell } from '@/components/ui/dialog'
import { EmptyState } from '@/components/ui/empty-state'
import { Field, Input, Select, Textarea } from '@/components/ui/field'

export function ModalHost() {
  const app = useApp()
  if (!app.modal) return null

  if (app.modal.type === 'server') return <ServerDialog />
  if (app.modal.type === 'credential') return <CredentialDialog />
  return <ConnectDialog protocol={app.modal.protocol} serverId={app.modal.serverId} />
}

function ServerDialog() {
  const app = useApp()
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
      app.showToast('服务器已添加')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && app.setModal(null)} title='添加服务器' description='保存主机基础信息后即可绑定凭据发起连接。'>
      <form className='grid grid-cols-1 gap-3 md:grid-cols-2' onSubmit={onSubmit}>
        <Field label='名称'><Input name='name' placeholder='生产网关' required /></Field>
        <Field label='主机地址'><Input name='host' placeholder='10.0.0.12 / example.com' required /></Field>
        <Field label='系统'><Select name='os' defaultValue='linux'><option value='linux'>Linux</option><option value='windows'>Windows</option></Select></Field>
        <Field label='分组'><Input name='group' placeholder='default' /></Field>
        <Field label='SSH 端口'><Input name='ssh_port' type='number' defaultValue={22} /></Field>
        <Field label='RDP 端口'><Input name='rdp_port' type='number' defaultValue={3389} /></Field>
        <Field label='描述' className='md:col-span-2'><Textarea name='description' placeholder='用途、环境、负责人等' /></Field>
        <div className='flex justify-end gap-2 md:col-span-2'>
          <Button type='button' variant='outline' onClick={() => app.setModal(null)}>取消</Button>
          <Button variant='primary' disabled={submitting}>保存服务器</Button>
        </div>
      </form>
    </DialogShell>
  )
}

function CredentialDialog() {
  const app = useApp()
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
      app.showToast('凭据已添加')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && app.setModal(null)} title='添加凭据' description='明文只在提交时发送一次，服务端加密落盘。'>
      <form className='grid grid-cols-1 gap-3 md:grid-cols-2' onSubmit={onSubmit}>
        <Field label='名称'><Input name='name' placeholder='root-key / windows-admin' required /></Field>
        <Field label='类型'>
          <Select name='type' defaultValue='ssh_password'>
            <option value='ssh_password'>SSH 密码</option>
            <option value='ssh_key'>SSH 私钥</option>
            <option value='rdp_password'>RDP 密码</option>
          </Select>
        </Field>
        <Field label='用户名'><Input name='username' placeholder='root / ubuntu / Administrator' required /></Field>
        <Field label='域 / 工作组'><Input name='domain' placeholder='可选' /></Field>
        <Field label='密码'><Input name='password' type='password' placeholder='可选' /></Field>
        <Field label='私钥 passphrase'><Input name='passphrase' type='password' placeholder='可选' /></Field>
        <Field label='私钥' className='md:col-span-2'><Textarea name='private_key' placeholder='-----BEGIN OPENSSH PRIVATE KEY-----' /></Field>
        <div className='flex justify-end gap-2 md:col-span-2'>
          <Button type='button' variant='outline' onClick={() => app.setModal(null)}>取消</Button>
          <Button variant='primary' disabled={submitting}>保存凭据</Button>
        </div>
      </form>
    </DialogShell>
  )
}

function ConnectDialog({ protocol, serverId }: { protocol: Protocol; serverId: string }) {
  const app = useApp()
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

  return (
    <DialogShell compact open onOpenChange={(open) => !open && app.setModal(null)} title={`连接到 ${server?.name || '服务器'}`} description={`${protocol.toUpperCase()} 会话将以全屏工作区打开。`}>
      {credentials.length ? (
        <form className='grid gap-4' onSubmit={onSubmit}>
          <Field label='凭据'>
            <Select name='credential_id'>
              {credentials.map((credential) => <option key={credential.id} value={credential.id}>{credential.name} ({credential.username})</option>)}
            </Select>
          </Field>
          <div className='flex flex-wrap gap-2'>
            <Badge>{server?.host || '-'}</Badge>
            <Badge>{protocol === 'ssh' ? `SSH ${server?.ssh_port || 22}` : `RDP ${server?.rdp_port || 3389}`}</Badge>
            <Badge>{protocol === 'rdp' ? '启用录屏目录' : 'PTY 终端'}</Badge>
          </div>
          <div className='flex justify-end gap-2'>
            <Button type='button' variant='outline' onClick={() => app.setModal(null)}>取消</Button>
            <Button variant='primary' disabled={submitting}>开始连接</Button>
          </div>
        </form>
      ) : (
        <div className='grid gap-4'>
          <EmptyState title={`没有可用的 ${protocol.toUpperCase()} 凭据`} body='请先创建对应类型的凭据，再发起连接。' />
          <div className='flex justify-end'>
            <Button variant='primary' onClick={() => app.setModal({ type: 'credential' })}>添加凭据</Button>
          </div>
        </div>
      )}
    </DialogShell>
  )
}
