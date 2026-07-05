import type { ColumnDef } from '@tanstack/react-table'
import { Link } from '@tanstack/react-router'
import { ArrowUpRight, Play, Plus, RefreshCw, Save } from 'lucide-react'
import { useMemo, useState } from 'react'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { CardStaggerContainer, CardStaggerItem } from '@/components/page-transition'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { DialogShell } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { apiRequest } from '@/lib/api'
import { platformDescription, platformLabel, type PlatformPageConfig } from '@/lib/platform'
import { cn, formatDate } from '@/lib/utils'
import type { PlatformItem } from '@/types'

interface PlatformFormState {
  name: string
  type: string
  status: string
  protocol: string
  host: string
  port: string
  username: string
  group: string
  description: string
}

const initialForm: PlatformFormState = {
  name: '',
  type: '',
  status: 'enabled',
  protocol: '',
  host: '',
  port: '',
  username: '',
  group: '',
  description: '',
}

export function PlatformPage({ config }: { config: PlatformPageConfig }) {
  if (config.kind === 'tools') return <ToolsPage config={config} />
  if (config.kind === 'monitor') return <MonitoringPage config={config} />
  if (config.kind === 'settings') return <PlatformSettingsPage config={config} />
  return <PlatformTablePage config={config} />
}

export function PlatformTablePage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const label = platformLabel(config, app.locale)
  const description = platformDescription(config, app.locale)
  const Icon = config.icon
  const rows = app.data.platform?.[config.collection] || []
  const [formOpen, setFormOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [form, setForm] = useState<PlatformFormState>(initialForm)

  const columns = useMemo<ColumnDef<PlatformItem>[]>(
    () => [
      {
        header: app.t('name'),
        cell: ({ row }) => (
          <div className='min-w-44'>
            <strong className='block truncate'>{row.original.name}</strong>
            <span className='block truncate text-xs text-muted-foreground'>{row.original.description || row.original.id}</span>
          </div>
        ),
      },
      {
        header: app.t('type', '类型'),
        cell: ({ row }) => <Badge tone='neutral'>{row.original.type || row.original.protocol || '-'}</Badge>,
      },
      {
        header: app.t('status'),
        cell: ({ row }) => <Badge tone={statusTone(row.original.status)}>{row.original.status || '-'}</Badge>,
      },
      { header: app.t('address'), cell: ({ row }) => row.original.host ? <span className='font-mono text-xs'>{row.original.host}{row.original.port ? `:${row.original.port}` : ''}</span> : '-' },
      { header: app.t('group'), accessorFn: (row) => row.group || row.owner_id || row.target_id || '-' },
      { header: app.t('createdAt'), cell: ({ row }) => formatDate(row.original.created_at) },
    ],
    [app]
  )

  const save = async () => {
    setSaving(true)
    try {
      await apiRequest(config.apiPath || `/api/admin/${config.collection}`, {
        method: 'POST',
        body: JSON.stringify({
          ...form,
          port: form.port ? Number(form.port) : 0,
          protocol: form.protocol || undefined,
        }),
      })
      setForm(initialForm)
      setFormOpen(false)
      await app.refresh(true)
      app.showToast(app.t('saved', '已保存'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <CardStaggerContainer>
      <CardStaggerItem>
        <Card>
          <CardHeader className='gap-3 max-sm:grid-cols-1'>
            <div>
              <CardTitle className='flex items-center gap-2'>
                <Icon className='size-5 text-primary' />
                {label}
              </CardTitle>
              <CardDescription>{description}</CardDescription>
            </div>
            <div className='flex flex-wrap justify-end gap-2 max-sm:justify-start'>
              <Button variant='outline' onClick={() => void app.refresh()}>
                <RefreshCw className='size-4' />
                {app.t('refresh', '刷新')}
              </Button>
              <Button variant='primary' onClick={() => setFormOpen(true)}>
                <Plus className='size-4' />
                {app.t('new', '新建')}
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={columns}
              data={rows}
              emptyTitle={app.t('empty', '暂无数据')}
              emptyBody={description}
              searchPlaceholder={app.t('filter', '关键词搜索')}
              getSearchText={(item) => [item.name, item.type, item.status, item.protocol, item.host, item.group, item.username, item.description, item.tags?.join(' ')].filter(Boolean).join(' ')}
            />
          </CardContent>
        </Card>
      </CardStaggerItem>
      <PlatformItemDialog
        title={`${app.t('new', '新建')} ${label}`}
        description={description}
        open={formOpen}
        saving={saving}
        form={form}
        onOpenChange={setFormOpen}
        onChange={(next) => setForm((current) => ({ ...current, ...next }))}
        onSave={() => void save()}
      />
    </CardStaggerContainer>
  )
}

function PlatformItemDialog({
  title,
  description,
  open,
  saving,
  form,
  onOpenChange,
  onChange,
  onSave,
}: {
  title: string
  description: string
  open: boolean
  saving: boolean
  form: PlatformFormState
  onOpenChange: (open: boolean) => void
  onChange: (form: Partial<PlatformFormState>) => void
  onSave: () => void
}) {
  const app = useApp()
  return (
    <DialogShell open={open} onOpenChange={onOpenChange} title={title} description={description}>
      <div className='grid gap-4'>
        <div className='grid gap-3 sm:grid-cols-2'>
          <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
          <Field label={app.t('type', '类型')}><Input value={form.type} onChange={(event) => onChange({ type: event.currentTarget.value })} /></Field>
          <Field label={app.t('status')}><Input value={form.status} onChange={(event) => onChange({ status: event.currentTarget.value })} /></Field>
          <Field label={app.t('protocol')}><Select value={form.protocol} onChange={(event) => onChange({ protocol: event.currentTarget.value })}>
            <option value=''>{app.t('none', '无')}</option>
            <option value='ssh'>SSH</option>
            <option value='rdp'>RDP</option>
            <option value='vnc'>VNC</option>
            <option value='http'>HTTP</option>
            <option value='database'>Database</option>
          </Select></Field>
          <Field label={app.t('address')}><Input value={form.host} onChange={(event) => onChange({ host: event.currentTarget.value })} /></Field>
          <Field label={app.t('ports')}><Input type='number' value={form.port} onChange={(event) => onChange({ port: event.currentTarget.value })} /></Field>
          <Field label={app.t('username', '用户')}><Input value={form.username} onChange={(event) => onChange({ username: event.currentTarget.value })} /></Field>
          <Field label={app.t('group')}><Input value={form.group} onChange={(event) => onChange({ group: event.currentTarget.value })} /></Field>
        </div>
        <Field label={app.t('details')}><Textarea value={form.description} onChange={(event) => onChange({ description: event.currentTarget.value })} /></Field>
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={() => onOpenChange(false)}>{app.t('cancel', '取消')}</Button>
          <Button variant='primary' onClick={onSave} disabled={saving || !form.name.trim()}>
            <Save className='size-4' />
            {saving ? app.t('saving', '保存中') : app.t('save', '保存')}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

export function PlatformSettingsPage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const items = app.data.platform?.[config.collection] || []
  const label = platformLabel(config, app.locale)
  const description = platformDescription(config, app.locale)
  const Icon = config.icon
  return (
    <CardStaggerContainer>
      <CardStaggerItem>
        <Card>
          <CardHeader>
            <div>
              <CardTitle className='flex items-center gap-2'><Icon className='size-5 text-primary' />{label}</CardTitle>
              <CardDescription>{description}</CardDescription>
            </div>
            <Button variant='outline' onClick={() => void app.refresh()}><RefreshCw className='size-4' />{app.t('refresh', '刷新')}</Button>
          </CardHeader>
          <CardContent>
            <div className='grid gap-3 lg:grid-cols-3'>
              {items.map((item) => (
                <article key={item.id} className='rounded-xl border border-border bg-background/60 p-4'>
                  <div className='flex items-start justify-between gap-3'>
                    <div>
                      <h3 className='text-sm font-semibold'>{item.name}</h3>
                      <p className='mt-1 text-xs leading-5 text-muted-foreground'>{item.description}</p>
                    </div>
                    <Badge tone={statusTone(item.status)}>{item.status || 'enabled'}</Badge>
                  </div>
                  <div className='mt-4 grid gap-2 text-xs text-muted-foreground'>
                    <span>{app.t('type', '类型')}: {item.type || '-'}</span>
                    <span>{app.t('updatedAt', '更新时间')}: {formatDate(item.updated_at)}</span>
                  </div>
                </article>
              ))}
            </div>
          </CardContent>
        </Card>
      </CardStaggerItem>
    </CardStaggerContainer>
  )
}

export function AccessPortalPage() {
  const app = useApp()
  const assets = app.data.platform?.assets || []
  const webAssets = app.data.platform?.web_assets || []
  const databaseAssets = app.data.platform?.database_assets || []
  const textAssets = assets.filter((item) => item.protocol === 'ssh')
  const desktopAssets = assets.filter((item) => item.protocol === 'rdp' || item.protocol === 'vnc')
  return (
    <div className='grid gap-4'>
      <section className='rounded-2xl border border-border bg-card p-5'>
        <div className='flex flex-wrap items-start justify-between gap-3'>
          <div>
            <p className='text-xs font-medium tracking-[0.14em] text-muted-foreground uppercase'>Access</p>
            <h1 className='mt-2 text-2xl font-semibold tracking-tight'>接入门户</h1>
            <p className='mt-2 max-w-2xl text-sm leading-6 text-muted-foreground'>普通用户在这里访问被授权的文本协议、图形协议、Web 资产和数据库资产。</p>
          </div>
          <Link to={'/app/assets' as never} className='inline-flex h-8 items-center gap-2 rounded-lg border border-border px-3 text-sm hover:bg-muted'>
            管理资产
            <ArrowUpRight className='size-4' />
          </Link>
        </div>
      </section>
      <AccessSection title='文本协议' items={textAssets} />
      <AccessSection title='图形协议' items={desktopAssets} />
      <AccessSection title='Web资产' items={webAssets} />
      <AccessSection title='数据库资产' items={databaseAssets} />
    </div>
  )
}

function AccessSection({ title, items }: { title: string; items: PlatformItem[] }) {
  const app = useApp()
  const connect = async (item: PlatformItem) => {
    try {
      await apiRequest(`/api/access/${item.protocol || 'ssh'}/${item.id}`, { method: 'POST', body: '{}' })
      await app.refresh(true)
      app.showToast('已创建接入会话')
    } catch (error) {
      app.handleApiError(error)
    }
  }
  return (
    <section className='grid gap-3'>
      <h2 className='text-sm font-semibold'>{title}</h2>
      {items.length ? (
        <div className='grid gap-3 md:grid-cols-2 xl:grid-cols-3'>
          {items.map((item) => (
            <article key={item.id} className='rounded-xl border border-border bg-card p-4'>
              <div className='flex items-start justify-between gap-3'>
                <div className='min-w-0'>
                  <h3 className='truncate text-sm font-semibold'>{item.name}</h3>
                  <p className='mt-1 truncate font-mono text-xs text-muted-foreground'>{item.host}{item.port ? `:${item.port}` : ''}</p>
                </div>
                <Badge tone={statusTone(item.status)}>{item.protocol || item.type || '-'}</Badge>
              </div>
              <p className='mt-3 line-clamp-2 text-xs leading-5 text-muted-foreground'>{item.description || item.group || item.id}</p>
              <Button className='mt-4 w-full' variant='primary' size='sm' onClick={() => void connect(item)}>
                <Play className='size-4' />
                接入
              </Button>
            </article>
          ))}
        </div>
      ) : (
        <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>暂无授权资源。</div>
      )}
    </section>
  )
}

function ToolsPage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const [target, setTarget] = useState('')
  const [mode, setMode] = useState('dns')
  const [result, setResult] = useState<Array<Record<string, unknown>>>([])
  const run = async () => {
    try {
      const data = await apiRequest<{ results: Array<Record<string, unknown>> }>(config.apiPath || '/api/tools/ping', {
        method: 'POST',
        body: JSON.stringify({ target, count: 4, mode }),
      })
      setResult(data.results || [])
    } catch (error) {
      app.handleApiError(error)
    }
  }
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>实用工具</CardTitle>
          <CardDescription>Ping / TCP Ping 检测目标地址连通性。</CardDescription>
        </div>
      </CardHeader>
      <CardContent className='grid gap-4'>
        <div className='grid gap-3 md:grid-cols-[minmax(0,1fr)_10rem_auto]'>
          <Input placeholder='请输入 IP、域名或 host:port' value={target} onChange={(event) => setTarget(event.currentTarget.value)} />
          <Select value={mode} onChange={(event) => setMode(event.currentTarget.value)}>
            <option value='dns'>Ping</option>
            <option value='tcp'>TCP Ping</option>
          </Select>
          <Button variant='primary' onClick={() => void run()} disabled={!target.trim()}><Play className='size-4' />开始检测</Button>
        </div>
        <div className='rounded-xl border border-border bg-background/60 p-3 font-mono text-xs'>
          {result.length ? result.map((row, index) => <div key={index}>{JSON.stringify(row)}</div>) : '暂无检测结果'}
        </div>
      </CardContent>
    </Card>
  )
}

function MonitoringPage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const [monitor, setMonitor] = useState<Record<string, unknown> | null>(null)
  const load = async () => {
    try {
      setMonitor(await apiRequest<Record<string, unknown>>(config.apiPath || '/api/system/monitoring'))
    } catch (error) {
      app.handleApiError(error)
    }
  }
  const stats = monitor || {
    users: app.data.platform?.users?.length || 0,
    assets: app.data.platform?.assets?.length || 0,
    web_assets: app.data.platform?.web_assets?.length || 0,
    database_assets: app.data.platform?.database_assets?.length || 0,
    active_sessions: app.data.platform?.online_sessions?.length || 0,
    recordings: app.data.platform?.offline_sessions?.length || 0,
  }
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>系统监控</CardTitle>
          <CardDescription>集中查看服务、网关、会话、存储和告警的运行状态。</CardDescription>
        </div>
        <Button variant='outline' onClick={() => void load()}><RefreshCw className='size-4' />刷新</Button>
      </CardHeader>
      <CardContent>
        <div className='grid gap-3 md:grid-cols-3 xl:grid-cols-4'>
          {Object.entries(stats).map(([key, value]) => (
            <div key={key} className='rounded-xl border border-border bg-background/60 p-4'>
              <div className='text-xs font-medium text-muted-foreground'>{key}</div>
              <div className={cn('mt-2 truncate font-mono text-xl font-semibold', value === 'normal' && 'text-success')}>{String(value)}</div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

function statusTone(status?: string) {
  const value = (status || '').toLowerCase()
  if (['active', 'enabled', 'success', 'normal', 'encrypted'].includes(value)) return 'success' as const
  if (['pending', 'disabled', 'offline'].includes(value)) return 'warning' as const
  if (['failed', 'locked', 'denied'].includes(value)) return 'danger' as const
  return 'neutral' as const
}
