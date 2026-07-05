import type { ColumnDef } from '@tanstack/react-table'
import { Link } from '@tanstack/react-router'
import { ArrowUpRight, Copy, Download, FileDown, FileSearch, FolderPlus, MoveRight, Pencil, Play, Plus, RefreshCw, Save, Trash2, Upload } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import { useApp } from '@/app/app-provider'
import { DataTable } from '@/components/data-table/data-table'
import { CardStaggerContainer, CardStaggerItem } from '@/components/page-transition'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { DialogShell } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { ApiError, apiRequest } from '@/lib/api'
import { platformDescription, platformLabel, platformPages, type PlatformPageConfig } from '@/lib/platform'
import { cn, formatDate } from '@/lib/utils'
import type { ConnectionSession, PlatformItem, Protocol } from '@/types'

interface PlatformFormState {
  name: string
  type: string
  status: string
  protocol: string
  host: string
  port: string
  username: string
  password: string
  private_key: string
  passphrase: string
  group: string
  owner_id: string
  parent_id: string
  target_id: string
  tags: string
  permissions: Record<string, boolean>
  metadata: string
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
  password: '',
  private_key: '',
  passphrase: '',
  group: '',
  owner_id: '',
  parent_id: '',
  target_id: '',
  tags: '',
  permissions: {},
  metadata: '',
  description: '',
}

const filePermissionActions = [
  { key: 'upload', labelKey: 'upload', labelZh: '上传' },
  { key: 'download', labelKey: 'download', labelZh: '下载' },
  { key: 'edit', labelKey: 'edit', labelZh: '编辑' },
  { key: 'delete', labelKey: 'delete', labelZh: '删除' },
  { key: 'rename', labelKey: 'rename', labelZh: '重命名' },
  { key: 'copy', labelKey: 'copy', labelZh: '复制' },
  { key: 'paste', labelKey: 'paste', labelZh: '粘贴' },
]

type ResourceOperation =
  | { type: 'asset-import' }
  | { type: 'agent-token'; item: PlatformItem }
  | { type: 'certificate-create' }
  | { type: 'storage-files'; item: PlatformItem }
  | { type: 'task-logs'; item: PlatformItem }
  | { type: 'sql-execute'; item: PlatformItem }

interface StorageEntry {
  name: string
  path: string
  is_dir: boolean
  size: number
  modified: string
}

interface BackupInfo {
  name: string
  size: number
  modified_at: string
  manifest?: Record<string, unknown>
  files?: string[]
}

export function PlatformPage({ config }: { config: PlatformPageConfig }) {
  if (config.kind === 'tools') return <ToolsPage config={config} />
  if (config.kind === 'monitor') return <MonitoringPage config={config} />
  if (config.kind === 'backups') return <BackupsPage config={config} />
  if (config.collection === 'access_stats') return <AccessStatsPage config={config} />
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
  const [editing, setEditing] = useState<PlatformItem | null>(null)
  const [form, setForm] = useState<PlatformFormState>(initialForm)
  const [operation, setOperation] = useState<ResourceOperation | null>(null)

  const columns = useMemo<ColumnDef<PlatformItem>[]>(
    () => [
      {
        header: app.t('name'),
        cell: ({ row }) => (
          <div className='min-w-44' style={config.collection === 'departments' ? { paddingLeft: `${departmentLevel(row.original) * 18}px` } : undefined}>
            <strong className='block truncate'>
              {config.collection === 'departments' && departmentLevel(row.original) > 0 ? '└ ' : ''}
              {row.original.name}
            </strong>
            <span className='block truncate text-xs text-muted-foreground'>
              {config.collection === 'departments' ? metadataText(row.original.metadata?.path) || row.original.description || row.original.id : row.original.description || row.original.id}
            </span>
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
      ...(config.collection === 'users' ? [
        {
          header: app.t('onlineStatus', '在线状态'),
          cell: ({ row }) => (
            <Badge tone={userOnline(row.original) ? 'success' : 'neutral'}>
              {userOnline(row.original) ? app.t('online', '在线') : app.t('offline', '离线')}
            </Badge>
          ),
        },
        {
          header: app.t('lastLogin', '最后登录'),
          cell: ({ row }) => (
            <div className='grid gap-0.5 text-xs'>
              <span>{formatDate(metadataText(row.original.metadata?.last_login_at))}</span>
              <span className='text-muted-foreground'>{metadataText(row.original.metadata?.last_login_ip) || '-'}</span>
            </div>
          ),
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'departments' ? [
        {
          header: app.t('members', '成员'),
          cell: ({ row }) => (
            <span className='font-mono text-xs'>
              {metadataNumber(row.original.metadata?.member_count)} / {metadataNumber(row.original.metadata?.total_member_count)}
            </span>
          ),
        },
        {
          header: app.t('sort', '排序'),
          cell: ({ row }) => <span className='font-mono text-xs'>{metadataNumber(row.original.metadata?.sort)}</span>,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'command_filters' ? [
        {
          header: app.t('commandPattern', '命令匹配'),
          cell: ({ row }) => <span className='font-mono text-xs'>{metadataText(row.original.metadata?.pattern) || '-'}</span>,
        },
        {
          header: app.t('riskLevel', '风险等级'),
          cell: ({ row }) => <Badge tone={riskTone(metadataText(row.original.metadata?.risk))}>{metadataText(row.original.metadata?.risk) || 'normal'}</Badge>,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'command_snippets' ? [
        {
          header: app.t('commandContent', '命令内容'),
          cell: ({ row }) => <span className='font-mono text-xs'>{metadataText(row.original.metadata?.command) || row.original.description || '-'}</span>,
        },
        {
          header: app.t('appendNewline', '自动回车'),
          cell: ({ row }) => <Badge tone={metadataBool(row.original.metadata?.append_newline) ? 'success' : 'neutral'}>{metadataBool(row.original.metadata?.append_newline) ? app.t('enabled', '启用') : app.t('disabled', '禁用')}</Badge>,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'authorization_strategies' ? [
        {
          header: app.t('permissionMatrix', '权限矩阵'),
          cell: ({ row }) => <span className='font-mono text-xs'>{permissionSummary(row.original.permissions)}</span>,
        },
        {
          header: app.t('pathPrefix', '路径前缀'),
          cell: ({ row }) => <span className='font-mono text-xs'>{metadataText(row.original.metadata?.path_prefix) || '*'}</span>,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(!['command_filters', 'command_snippets', 'authorization_strategies'].includes(config.collection) ? [
        { header: app.t('address'), cell: ({ row }) => row.original.host ? <span className='font-mono text-xs'>{row.original.host}{row.original.port ? `:${row.original.port}` : ''}</span> : '-' },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'agent_gateways' ? [
        { header: '延迟', cell: ({ row }) => <span className='font-mono text-xs'>{formatNumberValue(row.original.metadata?.latency_ms)} ms</span> },
        {
          header: '资源',
          cell: ({ row }) => (
            <span className='font-mono text-xs'>
              CPU {formatPercentValueFromWhole(row.original.metadata?.cpu_percent)} / MEM {formatPercentValueFromWhole(row.original.metadata?.memory_percent)}
            </span>
          ),
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      { header: app.t('group'), accessorFn: (row) => row.group || row.owner_id || row.target_id || '-' },
      { header: app.t('createdAt'), cell: ({ row }) => formatDate(row.original.created_at) },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className='flex justify-end gap-1.5'>
            <ResourceRowActions config={config} item={row.original} onOperation={setOperation} />
            <Button size='sm' variant='outline' onClick={() => startEdit(row.original)}>
              <Pencil className='size-3.5' />
              {app.t('edit', '编辑')}
            </Button>
            <Button size='sm' variant='destructive' onClick={() => void remove(row.original)}>
              <Trash2 className='size-3.5' />
              {app.t('delete', '删除')}
            </Button>
          </div>
        ),
      },
    ],
    [app, config]
  )

  const save = async () => {
    setSaving(true)
    try {
      const endpoint = editing ? `${config.apiPath || `/api/admin/${config.collection}`}/${editing.id}` : config.apiPath || `/api/admin/${config.collection}`
      await apiRequest(endpoint, {
        method: editing ? 'PATCH' : 'POST',
        body: JSON.stringify(platformRequestFromForm(form)),
      })
      setForm(initialForm)
      setEditing(null)
      setFormOpen(false)
      await app.refresh(true)
      app.showToast(app.t('saved', '已保存'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  const startCreate = () => {
    setEditing(null)
    setForm({
      ...initialForm,
      type: defaultPlatformType(config.collection),
      protocol: config.collection === 'command_filters' ? 'ssh' : '',
      permissions: defaultPlatformPermissions(config.collection),
      metadata: defaultPlatformMetadata(config.collection),
    })
    setFormOpen(true)
  }

  const startEdit = (item: PlatformItem) => {
    setEditing(item)
    setForm(formFromPlatformItem(item))
    setFormOpen(true)
  }

  const remove = async (item: PlatformItem) => {
    if (!window.confirm(`${app.t('delete', '删除')} ${item.name}?`)) return
    try {
      await apiRequest(`${config.apiPath || `/api/admin/${config.collection}`}/${item.id}`, { method: 'DELETE' })
      await app.refresh(true)
      app.showToast(app.t('deleted', '已删除'))
    } catch (error) {
      app.handleApiError(error)
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
              <ResourceHeaderActions config={config} onOperation={setOperation} />
              <Button variant='outline' onClick={() => void app.refresh()}>
                <RefreshCw className='size-4' />
                {app.t('refresh', '刷新')}
              </Button>
              <Button variant='primary' onClick={startCreate}>
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
              getSearchText={(item) => [item.name, item.type, item.status, item.protocol, item.host, item.group, item.username, item.description, metadataText(item.metadata?.pattern), metadataText(item.metadata?.command), metadataText(item.metadata?.risk), metadataText(item.metadata?.path_prefix), permissionSummary(item.permissions), metadataText(item.metadata?.last_login_at), metadataText(item.metadata?.last_login_ip), item.tags?.join(' ')].filter(Boolean).join(' ')}
            />
          </CardContent>
        </Card>
      </CardStaggerItem>
      <PlatformItemDialog
        title={`${editing ? app.t('edit', '编辑') : app.t('new', '新建')} ${label}`}
        description={description}
        collection={config.collection}
        open={formOpen}
        saving={saving}
        form={form}
        items={rows}
        editingId={editing?.id}
        onOpenChange={(open) => {
          setFormOpen(open)
          if (!open) setEditing(null)
        }}
        onChange={(next) => setForm((current) => ({ ...current, ...next }))}
        onSave={() => void save()}
      />
      <ResourceOperationDialog operation={operation} onOpenChange={setOperation} />
    </CardStaggerContainer>
  )
}

function ResourceHeaderActions({ config, onOperation }: { config: PlatformPageConfig; onOperation: (operation: ResourceOperation) => void }) {
  const app = useApp()

  const exportAssets = async () => {
    try {
      const data = await apiRequest<Record<string, unknown>>('/api/admin/assets/export')
      downloadText('openwebservermanager-assets.json', JSON.stringify(data, null, 2), 'application/json')
      app.showToast('资产已导出')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  if (config.collection === 'assets') {
    return (
      <>
        <Button variant='outline' onClick={() => void exportAssets()}>
          <Download className='size-4' />
          导出
        </Button>
        <Button variant='outline' onClick={() => onOperation({ type: 'asset-import' })}>
          <Upload className='size-4' />
          导入
        </Button>
      </>
    )
  }

  if (config.collection === 'certificates') {
    return (
      <Button variant='outline' onClick={() => onOperation({ type: 'certificate-create' })}>
        <Plus className='size-4' />
        自签证书
      </Button>
    )
  }

  return null
}

function ResourceRowActions({ config, item, onOperation }: { config: PlatformPageConfig; item: PlatformItem; onOperation: (operation: ResourceOperation) => void }) {
  const app = useApp()

  const runTask = async () => {
    try {
      await apiRequest(`/api/admin/scheduled-tasks/${item.id}/run`, { method: 'POST', body: '{}' })
      await app.refresh(true)
      app.showToast('任务已触发')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const downloadCertificate = async () => {
    try {
      await downloadResponse(`/api/admin/certificates/${item.id}/download`, `${item.name || item.id}.crt`)
      app.showToast('证书已下载')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const disconnectSession = async () => {
    if (!window.confirm(`断开 ${item.name || item.id}?`)) return
    try {
      await apiRequest(`/api/admin/audit/online-sessions/${item.id}/disconnect`, { method: 'POST', body: '{}' })
      await app.refresh(true)
      app.showToast('会话已断开')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const downloadRecording = async () => {
    try {
      await downloadResponse(`/api/admin/audit/offline-sessions/${item.id}/recording`, `${item.name || item.id}.zip`)
      app.showToast('录屏已下载')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const deleteRecording = async () => {
    if (!window.confirm(`删除 ${item.name || item.id} 的录屏?`)) return
    try {
      await apiRequest(`/api/admin/audit/offline-sessions/${item.id}/recording`, { method: 'DELETE' })
      await app.refresh(true)
      app.showToast('录屏已删除')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const approveSQLWorkOrder = async () => {
    try {
      await apiRequest(`/api/admin/sql-work-orders/${item.id}/approve`, { method: 'POST', body: '{}' })
      await app.refresh(true)
      app.showToast('SQL 工单已批准')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const rejectSQLWorkOrder = async () => {
    if (!window.confirm(`拒绝 ${item.name || item.id}?`)) return
    try {
      await apiRequest(`/api/admin/sql-work-orders/${item.id}/reject`, { method: 'POST', body: '{}' })
      await app.refresh(true)
      app.showToast('SQL 工单已拒绝')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  if (config.collection === 'online_sessions') {
    return (
      <Button size='sm' variant='destructive' onClick={() => void disconnectSession()}>
        <Trash2 className='size-3.5' />
        断开
      </Button>
    )
  }

  if (config.collection === 'offline_sessions' && itemHasRecording(item)) {
    return (
      <>
        <Button size='sm' variant='outline' onClick={() => void downloadRecording()}>
          <Download className='size-3.5' />
          下载录屏
        </Button>
        <Button size='sm' variant='destructive' onClick={() => void deleteRecording()}>
          <Trash2 className='size-3.5' />
          删除录屏
        </Button>
      </>
    )
  }

  if (config.collection === 'storages') {
    return (
      <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'storage-files', item })}>
        <FileSearch className='size-3.5' />
        文件
      </Button>
    )
  }

  if (config.collection === 'certificates') {
    return (
      <Button size='sm' variant='outline' onClick={() => void downloadCertificate()}>
        <FileDown className='size-3.5' />
        下载
      </Button>
    )
  }

  if (config.collection === 'agent_gateways') {
    return (
      <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'agent-token', item })}>
        <Copy className='size-3.5' />
        令牌
      </Button>
    )
  }

  if (config.collection === 'scheduled_tasks') {
    return (
      <>
        <Button size='sm' variant='outline' onClick={() => void runTask()}>
          <Play className='size-3.5' />
          运行
        </Button>
        <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'task-logs', item })}>
          <FileSearch className='size-3.5' />
          日志
        </Button>
      </>
    )
  }

  if (config.collection === 'sql_work_orders') {
    const status = (item.status || '').toLowerCase()
    if (status === 'pending' || status === 'submitted' || status === 'requested') {
      return (
        <>
          <Button size='sm' variant='outline' onClick={() => void approveSQLWorkOrder()}>
            <Save className='size-3.5' />
            批准
          </Button>
          <Button size='sm' variant='destructive' onClick={() => void rejectSQLWorkOrder()}>
            <Trash2 className='size-3.5' />
            拒绝
          </Button>
        </>
      )
    }
    if (status !== 'approved') return null
    return (
      <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'sql-execute', item })}>
        <Play className='size-3.5' />
        执行
      </Button>
    )
  }

  return null
}

function ResourceOperationDialog({ operation, onOpenChange }: { operation: ResourceOperation | null; onOpenChange: (operation: ResourceOperation | null) => void }) {
  if (!operation) return null
  if (operation.type === 'asset-import') return <AssetImportDialog onClose={() => onOpenChange(null)} />
  if (operation.type === 'agent-token') return <AgentGatewayTokenDialog item={operation.item} onClose={() => onOpenChange(null)} />
  if (operation.type === 'certificate-create') return <CertificateCreateDialog onClose={() => onOpenChange(null)} />
  if (operation.type === 'storage-files') return <StorageFilesDialog item={operation.item} onClose={() => onOpenChange(null)} />
  if (operation.type === 'task-logs') return <TaskLogsDialog item={operation.item} onClose={() => onOpenChange(null)} />
  return <SQLExecuteDialog item={operation.item} onClose={() => onOpenChange(null)} />
}

function AssetImportDialog({ onClose }: { onClose: () => void }) {
  const app = useApp()
  const [content, setContent] = useState('{\n  "items": []\n}')
  const [saving, setSaving] = useState(false)

  const submit = async () => {
    setSaving(true)
    try {
      const parsed = JSON.parse(content) as unknown
      const payload = Array.isArray(parsed) ? { items: parsed } : parsed
      await apiRequest('/api/admin/assets/import', { method: 'POST', body: JSON.stringify(payload) })
      await app.refresh(true)
      app.showToast('资产已导入')
      onClose()
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title='导入资产' description='粘贴导出的 JSON，或使用 {"items":[...]} 格式批量导入。'>
      <div className='grid gap-4'>
        <Field label='资产 JSON'><Textarea className='min-h-64 font-mono text-xs' value={content} onChange={(event) => setContent(event.currentTarget.value)} /></Field>
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>取消</Button>
          <Button variant='primary' onClick={() => void submit()} disabled={saving}>
            <Upload className='size-4' />
            {saving ? '导入中' : '导入'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function AgentGatewayTokenDialog({ item, onClose }: { item: PlatformItem; onClose: () => void }) {
  const app = useApp()
  const [loading, setLoading] = useState(true)
  const [token, setToken] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    let alive = true
    const issue = async () => {
      setLoading(true)
      setError('')
      try {
        const data = await apiRequest<{ registration_token: string; gateway_id: string }>(`/api/admin/agent-gateways/${item.id}/token`, {
          method: 'POST',
          body: '{}',
        })
        if (!alive) return
        setToken(data.registration_token || '')
        await app.refresh(true)
      } catch (requestError) {
        if (!alive) return
        const message = requestError instanceof Error ? requestError.message : '生成令牌失败'
        setError(message)
      } finally {
        if (alive) setLoading(false)
      }
    }
    void issue()
    return () => {
      alive = false
    }
  }, [app, item.id])

  const server = window.location.origin
  const registerPayload = JSON.stringify({ registration_token: token, hostname: 'gateway-01', version: '1.0.0' }, null, 2)
  const heartbeatPayload = JSON.stringify({ registration_token: token, latency_ms: 12, cpu_percent: 8.5, memory_used_bytes: 268435456, memory_total_bytes: 1073741824 }, null, 2)

  const copy = async (value: string, message = '已复制') => {
    await navigator.clipboard.writeText(value)
    app.showToast(message)
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title='Agent 注册令牌' description='令牌只显示一次；重新生成会让旧令牌失效。'>
      <div className='grid gap-4'>
        {loading ? (
          <div className='rounded-lg border border-border bg-muted/50 p-4 text-sm text-muted-foreground'>正在生成令牌...</div>
        ) : error ? (
          <div className='rounded-lg border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive'>{error}</div>
        ) : (
          <>
            <Field label='Gateway ID'><Input readOnly value={item.id} /></Field>
            <Field label='Registration Token'>
              <div className='grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto]'>
                <Input readOnly className='font-mono text-xs' value={token} />
                <Button variant='outline' onClick={() => void copy(token)}>
                  <Copy className='size-4' />
                  复制
                </Button>
              </div>
            </Field>
            <div className='grid gap-3'>
              <div className='rounded-lg border border-border bg-background/70 p-3'>
                <div className='mb-2 text-xs font-medium text-muted-foreground'>注册请求</div>
                <pre className='overflow-auto rounded-md bg-muted p-3 text-xs'>{`curl -X POST ${server}/api/agent/gateways/register \\\n  -H "Content-Type: application/json" \\\n  -d '${registerPayload}'`}</pre>
              </div>
              <div className='rounded-lg border border-border bg-background/70 p-3'>
                <div className='mb-2 text-xs font-medium text-muted-foreground'>心跳请求</div>
                <pre className='overflow-auto rounded-md bg-muted p-3 text-xs'>{`curl -X POST ${server}/api/agent/gateways/heartbeat \\\n  -H "Content-Type: application/json" \\\n  -d '${heartbeatPayload}'`}</pre>
              </div>
            </div>
          </>
        )}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>关闭</Button>
          {token ? (
            <Button variant='primary' onClick={() => void copy(token, '注册令牌已复制')}>
              <Copy className='size-4' />
              复制令牌
            </Button>
          ) : null}
        </div>
      </div>
    </DialogShell>
  )
}

function CertificateCreateDialog({ onClose }: { onClose: () => void }) {
  const app = useApp()
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [dns, setDNS] = useState('')
  const [ip, setIP] = useState('')
  const [days, setDays] = useState('365')
  const [saving, setSaving] = useState(false)

  const submit = async () => {
    setSaving(true)
    try {
      await apiRequest('/api/admin/certificates/self-signed', {
        method: 'POST',
        body: JSON.stringify({
          name,
          domain,
          dns: splitCSV(dns),
          ip: splitCSV(ip),
          days: Number(days) || 365,
        }),
      })
      await app.refresh(true)
      app.showToast('自签证书已生成')
      onClose()
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title='生成自签证书' description='生成后会写入证书管理，可从行内操作下载 PEM 证书。'>
      <div className='grid gap-4'>
        <div className='grid gap-3 sm:grid-cols-2'>
          <Field label='名称'><Input value={name} onChange={(event) => setName(event.currentTarget.value)} /></Field>
          <Field label='主域名'><Input value={domain} onChange={(event) => setDomain(event.currentTarget.value)} placeholder='example.com' /></Field>
          <Field label='DNS SAN'><Input value={dns} onChange={(event) => setDNS(event.currentTarget.value)} placeholder='www.example.com,api.example.com' /></Field>
          <Field label='IP SAN'><Input value={ip} onChange={(event) => setIP(event.currentTarget.value)} placeholder='127.0.0.1,10.0.0.1' /></Field>
          <Field label='有效天数'><Input type='number' value={days} onChange={(event) => setDays(event.currentTarget.value)} /></Field>
        </div>
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>取消</Button>
          <Button variant='primary' onClick={() => void submit()} disabled={saving || !domain.trim()}>
            <Save className='size-4' />
            {saving ? '生成中' : '生成'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function StorageFilesDialog({ item, onClose }: { item: PlatformItem; onClose: () => void }) {
  const app = useApp()
  const [path, setPath] = useState('.')
  const [entries, setEntries] = useState<StorageEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [folderName, setFolderName] = useState('')
  const [filePath, setFilePath] = useState('')
  const [fileContent, setFileContent] = useState('')
  const [copySource, setCopySource] = useState('')
  const [copyDestination, setCopyDestination] = useState('')
  const [renameSource, setRenameSource] = useState('')
  const [renameDestination, setRenameDestination] = useState('')
  const [uploadFileItem, setUploadFileItem] = useState<File | null>(null)
  const [uploadInputKey, setUploadInputKey] = useState(0)

  const load = async (target = path) => {
    setLoading(true)
    try {
      const data = await apiRequest<{ path: string; entries: StorageEntry[] }>(`/api/admin/storages/${item.id}/files?path=${encodeURIComponent(target)}`)
      setPath(data.path || '.')
      setEntries(data.entries || [])
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load('.')
  }, [item.id])

  const createFolder = async () => {
    try {
      await apiRequest(`/api/admin/storages/${item.id}/files-mkdir`, {
        method: 'POST',
        body: JSON.stringify({ path: joinStoragePath(path, folderName) }),
      })
      setFolderName('')
      await load()
      await app.refresh(true)
      app.showToast('目录已创建')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const writeFile = async () => {
    try {
      await apiRequest(`/api/admin/storages/${item.id}/files-write`, {
        method: 'POST',
        body: JSON.stringify({ path: joinStoragePath(path, filePath), content: fileContent }),
      })
      setFilePath('')
      setFileContent('')
      await load()
      await app.refresh(true)
      app.showToast('文件已写入')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const uploadSelectedFile = async () => {
    if (!uploadFileItem) return
    try {
      const form = new FormData()
      form.set('path', path === '.' ? '' : path)
      form.set('file', uploadFileItem)
      const response = await fetch(`/api/admin/storages/${item.id}/files-upload`, {
        method: 'POST',
        credentials: 'same-origin',
        body: form,
      })
      const payload = (await response.json().catch(() => ({}))) as { error?: string; setup_required?: boolean }
      if (!response.ok) {
        throw new ApiError(payload.error || response.statusText, response.status, Boolean(payload.setup_required))
      }
      setUploadFileItem(null)
      setUploadInputKey((value) => value + 1)
      await load()
      await app.refresh(true)
      app.showToast('文件已上传')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const deleteEntry = async (entry: StorageEntry) => {
    if (!window.confirm(`删除 ${entry.path}?`)) return
    try {
      await apiRequest(`/api/admin/storages/${item.id}/files?path=${encodeURIComponent(entry.path)}`, { method: 'DELETE' })
      await load()
      await app.refresh(true)
      app.showToast('文件已删除')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const downloadEntry = async (entry: StorageEntry) => {
    try {
      await downloadResponse(`/api/admin/storages/${item.id}/files-download?path=${encodeURIComponent(entry.path)}`, entry.name)
      app.showToast('文件已下载')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const copyEntry = async () => {
    try {
      await apiRequest(`/api/admin/storages/${item.id}/files-copy`, {
        method: 'POST',
        body: JSON.stringify({ path: joinStoragePath(path, copySource), destination: joinStoragePath(path, copyDestination) }),
      })
      setCopySource('')
      setCopyDestination('')
      await load()
      await app.refresh(true)
      app.showToast('文件已复制')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const renameEntry = async () => {
    try {
      await apiRequest(`/api/admin/storages/${item.id}/files-rename`, {
        method: 'POST',
        body: JSON.stringify({ path: joinStoragePath(path, renameSource), destination: joinStoragePath(path, renameDestination) }),
      })
      setRenameSource('')
      setRenameDestination('')
      await load()
      await app.refresh(true)
      app.showToast('文件已重命名')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} 文件`} description='浏览文件盘，创建目录，写入、下载和删除文件，操作会写入文件日志。'>
      <div className='grid gap-4'>
        <div className='grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto_auto]'>
          <Input value={path} onChange={(event) => setPath(event.currentTarget.value)} />
          <Button variant='outline' onClick={() => void load()} disabled={loading}><RefreshCw className='size-4' />打开</Button>
          <Button variant='outline' onClick={() => void load(parentStoragePath(path))} disabled={path === '.' || loading}>上级</Button>
        </div>
        <div className='grid gap-2 rounded-xl border border-border bg-background/60 p-3'>
          {entries.length ? entries.map((entry) => (
            <div key={entry.path} className='grid gap-2 rounded-lg border border-border bg-card p-2 text-sm sm:grid-cols-[minmax(0,1fr)_7rem_auto] sm:items-center'>
              <button className='min-w-0 text-left' onClick={() => entry.is_dir && void load(entry.path)}>
                <span className='block truncate font-medium'>{entry.is_dir ? '目录' : '文件'} / {entry.name}</span>
                <span className='block truncate text-xs text-muted-foreground'>{entry.path} · {entry.size} B · {formatDate(entry.modified)}</span>
              </button>
              <Badge tone={entry.is_dir ? 'neutral' : 'success'}>{entry.is_dir ? 'dir' : 'file'}</Badge>
              <div className='flex justify-end gap-1.5'>
                {!entry.is_dir ? (
                  <Button size='sm' variant='outline' onClick={() => void downloadEntry(entry)}><Download className='size-3.5' />下载</Button>
                ) : null}
                <Button size='sm' variant='destructive' onClick={() => void deleteEntry(entry)}><Trash2 className='size-3.5' />删除</Button>
              </div>
            </div>
          )) : (
            <div className='rounded-lg border border-dashed border-border p-6 text-sm text-muted-foreground'>{loading ? '加载中' : '当前目录为空'}</div>
          )}
        </div>
        <div className='grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]'>
          <Input placeholder='新目录名' value={folderName} onChange={(event) => setFolderName(event.currentTarget.value)} />
          <Button variant='outline' onClick={() => void createFolder()} disabled={!folderName.trim()}><FolderPlus className='size-4' />创建目录</Button>
        </div>
        <div className='grid gap-3 rounded-xl border border-border bg-background/60 p-3 sm:grid-cols-[minmax(0,1fr)_auto]'>
          <Input key={uploadInputKey} type='file' onChange={(event) => setUploadFileItem(event.currentTarget.files?.[0] || null)} />
          <Button variant='outline' onClick={() => void uploadSelectedFile()} disabled={!uploadFileItem}>
            <Upload className='size-4' />
            上传
          </Button>
        </div>
        <div className='grid gap-3 rounded-xl border border-border bg-background/60 p-3'>
          <div className='grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]'>
            <Input placeholder='复制源，例如 docs/a.txt' value={copySource} onChange={(event) => setCopySource(event.currentTarget.value)} />
            <Input placeholder='复制到，例如 docs/b.txt' value={copyDestination} onChange={(event) => setCopyDestination(event.currentTarget.value)} />
            <Button variant='outline' onClick={() => void copyEntry()} disabled={!copySource.trim() || !copyDestination.trim()}>
              <Copy className='size-4' />
              复制
            </Button>
          </div>
          <div className='grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]'>
            <Input placeholder='重命名源，例如 docs/b.txt' value={renameSource} onChange={(event) => setRenameSource(event.currentTarget.value)} />
            <Input placeholder='改为，例如 docs/c.txt' value={renameDestination} onChange={(event) => setRenameDestination(event.currentTarget.value)} />
            <Button variant='outline' onClick={() => void renameEntry()} disabled={!renameSource.trim() || !renameDestination.trim()}>
              <MoveRight className='size-4' />
              重命名
            </Button>
          </div>
        </div>
        <div className='grid gap-3'>
          <Input placeholder='文件名，例如 notes/readme.txt' value={filePath} onChange={(event) => setFilePath(event.currentTarget.value)} />
          <Textarea placeholder='文件内容' value={fileContent} onChange={(event) => setFileContent(event.currentTarget.value)} />
          <div className='flex justify-end gap-2'>
            <Button variant='outline' onClick={onClose}>关闭</Button>
            <Button variant='primary' onClick={() => void writeFile()} disabled={!filePath.trim()}><Save className='size-4' />写入文件</Button>
          </div>
        </div>
      </div>
    </DialogShell>
  )
}

function TaskLogsDialog({ item, onClose }: { item: PlatformItem; onClose: () => void }) {
  const app = useApp()
  const [logs, setLogs] = useState<PlatformItem[]>([])

  const load = async () => {
    try {
      const data = await apiRequest<{ items: PlatformItem[] }>(`/api/admin/scheduled-tasks/${item.id}/logs`)
      setLogs(data.items || [])
    } catch (error) {
      app.handleApiError(error)
    }
  }

  useEffect(() => {
    void load()
  }, [item.id])

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} 运行日志`} description='查看该定时任务的手动和自动运行记录。'>
      <div className='grid gap-3'>
        <div className='flex justify-end'>
          <Button variant='outline' onClick={() => void load()}><RefreshCw className='size-4' />刷新</Button>
        </div>
        {logs.length ? logs.map((log) => (
          <article key={log.id} className='rounded-xl border border-border bg-background/60 p-3 text-sm'>
            <div className='flex items-center justify-between gap-3'>
              <strong>{log.name}</strong>
              <Badge tone={statusTone(log.status)}>{log.status}</Badge>
            </div>
            <p className='mt-2 text-xs text-muted-foreground'>{log.description || log.id}</p>
            <pre className='mt-3 overflow-auto rounded-lg bg-muted p-2 text-xs'>{JSON.stringify(log.metadata || {}, null, 2)}</pre>
          </article>
        )) : (
          <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>暂无运行日志。</div>
        )}
      </div>
    </DialogShell>
  )
}

function SQLExecuteDialog({
  item,
  onClose,
  endpoint,
  workOrderEndpoint,
  initialSQL,
  successMessage,
  workOrderMessage,
  description,
}: {
  item: PlatformItem
  onClose: () => void
  endpoint?: string
  workOrderEndpoint?: string
  initialSQL?: string
  successMessage?: string
  workOrderMessage?: string
  description?: string
}) {
  const app = useApp()
  const [sql, setSQL] = useState(initialSQL ?? stringValue(item.metadata?.sql))
  const [reason, setReason] = useState('')
  const [result, setResult] = useState<PlatformItem | null>(null)
  const [running, setRunning] = useState(false)
  const [submittingWorkOrder, setSubmittingWorkOrder] = useState(false)

  const execute = async () => {
    setRunning(true)
    try {
      const data = await apiRequest<PlatformItem>(endpoint || `/api/admin/sql-work-orders/${item.id}/execute`, {
        method: 'POST',
        body: JSON.stringify({ sql }),
      })
      setResult(data)
      await app.refresh(true)
      app.showToast(successMessage || 'SQL 工单已执行')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setRunning(false)
    }
  }

  const submitWorkOrder = async () => {
    if (!workOrderEndpoint) return
    setSubmittingWorkOrder(true)
    try {
      const data = await apiRequest<PlatformItem>(workOrderEndpoint, {
        method: 'POST',
        body: JSON.stringify({ sql, reason }),
      })
      setResult(data)
      setReason('')
      await app.refresh(true)
      app.showToast(workOrderMessage || 'SQL 工单已提交')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSubmittingWorkOrder(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} 执行`} description={description || '执行结果会写入 SQL 日志；SELECT 查询最多展示前 100 行。'}>
      <div className='grid gap-4'>
        <Field label='SQL'><Textarea className='min-h-44 font-mono text-xs' value={sql} onChange={(event) => setSQL(event.currentTarget.value)} /></Field>
        {workOrderEndpoint ? (
          <Field label='申请原因'><Input value={reason} onChange={(event) => setReason(event.currentTarget.value)} placeholder='说明变更目的、窗口或审批理由' /></Field>
        ) : null}
        {result ? <SQLResultPanel result={result} /> : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>关闭</Button>
          {workOrderEndpoint ? (
            <Button variant='outline' onClick={() => void submitWorkOrder()} disabled={submittingWorkOrder || !sql.trim()}>
              <Plus className='size-4' />
              {submittingWorkOrder ? '提交中' : '提交工单'}
            </Button>
          ) : null}
          <Button variant='primary' onClick={() => void execute()} disabled={running || !sql.trim()}>
            <Play className='size-4' />
            {running ? '执行中' : '执行'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function SQLResultPanel({ result }: { result: PlatformItem }) {
  const columns = stringArrayValue(result.metadata?.columns)
  const rows = objectArrayValue(result.metadata?.rows)
  return (
    <div className='rounded-xl border border-border bg-background/60 p-3'>
      <div className='flex items-center justify-between gap-3 text-sm'>
        <strong>{result.description || result.name}</strong>
        <Badge tone={statusTone(result.status)}>{result.status}</Badge>
      </div>
      {columns.length && rows.length ? (
        <div className='mt-3 max-h-80 overflow-auto rounded-lg border border-border'>
          <table className='min-w-full text-left text-xs'>
            <thead className='bg-muted text-muted-foreground'>
              <tr>
                {columns.map((column) => <th key={column} className='whitespace-nowrap px-3 py-2 font-medium'>{column}</th>)}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={index} className='border-t border-border'>
                  {columns.map((column) => <td key={column} className='whitespace-nowrap px-3 py-2 font-mono'>{String(row[column] ?? '')}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      <pre className='mt-3 max-h-80 overflow-auto rounded-lg bg-muted p-2 text-xs'>{JSON.stringify(result.metadata || {}, null, 2)}</pre>
    </div>
  )
}

function PlatformItemDialog({
  title,
  description,
  collection,
  open,
  saving,
  form,
  items,
  editingId,
  onOpenChange,
  onChange,
  onSave,
}: {
  title: string
  description: string
  collection: string
  open: boolean
  saving: boolean
  form: PlatformFormState
  items: PlatformItem[]
  editingId?: string
  onOpenChange: (open: boolean) => void
  onChange: (form: Partial<PlatformFormState>) => void
  onSave: () => void
}) {
  const app = useApp()
  const isCredential = collection === 'credentials'
  const isUser = collection === 'users'
  const isDepartment = collection === 'departments'
  const isRole = collection === 'roles'
  const isCommandFilter = collection === 'command_filters'
  const isCommandSnippet = collection === 'command_snippets'
  const isAuthorizationStrategy = collection === 'authorization_strategies'
  const roleItems = app.data.platform?.roles || []
  const storageItems = app.data.platform?.storages || []
  return (
    <DialogShell open={open} onOpenChange={onOpenChange} title={title} description={description}>
      <div className='grid gap-4'>
        <div className='grid gap-3 sm:grid-cols-2'>
          {isCommandFilter ? (
            <>
              <Field label={app.t('ruleName', '规则名称')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('status')}>
                <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                  <option value='enabled'>{app.t('enabled', '启用')}</option>
                  <option value='disabled'>{app.t('disabled', '禁用')}</option>
                </Select>
              </Field>
              <Field label={app.t('action', '动作')}>
                <Select value={form.type || 'deny'} onChange={(event) => onChange({ type: event.currentTarget.value })}>
                  <option value='deny'>{app.t('deny', '拒绝')}</option>
                  <option value='approval'>{app.t('approval', '审批')}</option>
                  <option value='allow'>{app.t('allow', '允许')}</option>
                </Select>
              </Field>
              <Field label={app.t('riskLevel', '风险等级')}>
                <Select value={metadataFormText(form.metadata, 'risk') || 'high'} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'risk', event.currentTarget.value) })}>
                  <option value='low'>{app.t('low', '低')}</option>
                  <option value='medium'>{app.t('medium', '中')}</option>
                  <option value='high'>{app.t('high', '高')}</option>
                  <option value='critical'>{app.t('critical', '严重')}</option>
                </Select>
              </Field>
              <Field className='sm:col-span-2' label={app.t('commandPattern', '命令匹配表达式')}>
                <Textarea
                  value={metadataFormText(form.metadata, 'pattern')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'pattern', event.currentTarget.value) })}
                  placeholder={'rm\\s+-rf|mkfs|shutdown|reboot'}
                />
              </Field>
              <Field label={app.t('protocol')}>
                <Select value={form.protocol || 'ssh'} onChange={(event) => onChange({ protocol: event.currentTarget.value })}>
                  <option value='ssh'>SSH</option>
                </Select>
              </Field>
              <Field label={app.t('targetAsset', '适用资产')}>
                <Input placeholder={app.t('emptyMeansAllAssets', '留空表示全部资产')} value={form.target_id} onChange={(event) => onChange({ target_id: event.currentTarget.value })} />
              </Field>
              <Field label={app.t('owner', '归属用户/部门')}>
                <Input placeholder={app.t('emptyMeansAllUsers', '留空表示全部用户')} value={form.owner_id} onChange={(event) => onChange({ owner_id: event.currentTarget.value })} />
              </Field>
              <Field label={app.t('tags', '标签')}><Input placeholder='prod,linux,web' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
            </>
          ) : isAuthorizationStrategy ? (
            <>
              <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('status')}>
                <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                  <option value='enabled'>{app.t('enabled', '启用')}</option>
                  <option value='disabled'>{app.t('disabled', '禁用')}</option>
                </Select>
              </Field>
              <Field label={app.t('type', '类型')}>
                <Select value={form.type || 'file'} onChange={(event) => onChange({ type: event.currentTarget.value })}>
                  <option value='file'>{app.t('filePermissionStrategy', '文件权限策略')}</option>
                </Select>
              </Field>
              <Field label={app.t('targetStorage', '目标存储')}>
                <Select value={form.target_id} onChange={(event) => onChange({ target_id: event.currentTarget.value })}>
                  <option value=''>{app.t('allStorages', '全部存储')}</option>
                  {storageItems.map((storage) => (
                    <option key={storage.id} value={storage.id}>{storage.name}</option>
                  ))}
                </Select>
              </Field>
              <Field label={app.t('owner', '适用用户/部门')}>
                <Input placeholder={app.t('emptyMeansAllUsers', '留空表示全部用户')} value={form.owner_id} onChange={(event) => onChange({ owner_id: event.currentTarget.value })} />
              </Field>
              <Field label={app.t('pathPrefix', '路径前缀')}>
                <Input placeholder={app.t('emptyMeansAllPaths', '留空表示全部路径')} value={metadataFormText(form.metadata, 'path_prefix')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'path_prefix', event.currentTarget.value) })} />
              </Field>
              <div className='grid gap-2 rounded-lg border border-border bg-muted/20 p-3 sm:col-span-2'>
                <div className='text-sm font-medium'>{app.t('permissionMatrix', '权限矩阵')}</div>
                <div className='grid gap-2 sm:grid-cols-2 lg:grid-cols-4'>
                  {filePermissionActions.map((action) => (
                    <label key={action.key} className='flex items-center justify-between gap-3 rounded-md border border-border bg-background px-3 py-2 text-sm'>
                      <span>{app.t(action.labelKey, action.labelZh)}</span>
                      <input
                        type='checkbox'
                        className='size-4 accent-primary'
                        checked={Boolean(form.permissions[action.key])}
                        onChange={(event) => onChange({ permissions: { ...form.permissions, [action.key]: event.currentTarget.checked } })}
                      />
                    </label>
                  ))}
                </div>
              </div>
              <Field label={app.t('tags', '标签')}><Input placeholder='storage,readonly' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
            </>
          ) : isCommandSnippet ? (
            <>
              <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('visibility', '可见性')}>
                <Select value={form.type || 'public'} onChange={(event) => onChange({ type: event.currentTarget.value })}>
                  <option value='public'>{app.t('public', '公开')}</option>
                  <option value='private'>{app.t('private', '私有')}</option>
                </Select>
              </Field>
              <Field label={app.t('status')}>
                <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                  <option value='enabled'>{app.t('enabled', '启用')}</option>
                  <option value='disabled'>{app.t('disabled', '禁用')}</option>
                </Select>
              </Field>
              <Field label={app.t('owner', '归属用户/部门')}>
                <Input placeholder={form.type === 'private' ? app.t('privateOwnerRequired', '私有片段建议填写用户 ID') : app.t('optional', '可选')} value={form.owner_id} onChange={(event) => onChange({ owner_id: event.currentTarget.value })} />
              </Field>
              <Field className='sm:col-span-2' label={app.t('commandContent', '命令内容')}>
                <Textarea
                  value={metadataFormText(form.metadata, 'command')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'command', event.currentTarget.value) })}
                  placeholder='uptime'
                />
              </Field>
              <label className='flex items-center gap-2 rounded-lg border border-border bg-muted/20 px-3 py-2 text-sm sm:col-span-2'>
                <input
                  type='checkbox'
                  className='size-4 accent-primary'
                  checked={metadataBoolFromForm(form.metadata, 'append_newline')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'append_newline', event.currentTarget.checked) })}
                />
                <span>{app.t('appendNewline', '插入后自动回车执行')}</span>
              </label>
              <Field label={app.t('group')}><Input value={form.group} onChange={(event) => onChange({ group: event.currentTarget.value })} /></Field>
              <Field label={app.t('tags', '标签')}><Input placeholder='linux,database' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
            </>
          ) : (
            <>
              <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('type', '类型')}>
                {isCredential ? (
                  <Select value={form.type} onChange={(event) => onChange({ type: event.currentTarget.value })}>
                    <option value='ssh_password'>SSH password</option>
                    <option value='ssh_key'>SSH private key</option>
                    <option value='rdp_password'>RDP password</option>
                    <option value='vnc_password'>VNC password</option>
                    <option value='database_password'>Database password</option>
                  </Select>
                ) : (
                  <Input value={form.type} onChange={(event) => onChange({ type: event.currentTarget.value })} />
                )}
              </Field>
              <Field label={app.t('status')}>
                {isUser ? (
                  <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                    <option value='enabled'>{app.t('enabled', '启用')}</option>
                    <option value='disabled'>{app.t('disabled', '禁用')}</option>
                  </Select>
                ) : (
                  <Input value={form.status} onChange={(event) => onChange({ status: event.currentTarget.value })} />
                )}
              </Field>
              <Field label={app.t('protocol')}><Select value={form.protocol} onChange={(event) => onChange({ protocol: event.currentTarget.value })}>
                <option value=''>{app.t('none', '无')}</option>
                <option value='ssh'>SSH</option>
                <option value='rdp'>RDP</option>
                <option value='vnc'>VNC</option>
                <option value='http'>HTTP</option>
                <option value='database'>Database</option>
              </Select></Field>
              <Field label={app.t('address')}><Input value={form.host} onChange={(event) => onChange({ host: event.currentTarget.value })} /></Field>
              <Field label={isDepartment ? app.t('sort', '排序') : app.t('ports')}>
                <Input type='number' value={form.port} onChange={(event) => onChange({ port: event.currentTarget.value })} />
              </Field>
              <Field label={app.t('username', '用户')}><Input value={form.username} onChange={(event) => onChange({ username: event.currentTarget.value })} /></Field>
              {isUser ? (
                <Field label={app.t('role', '角色')}>
                  <Select value={roleValue(form.metadata)} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'role', event.currentTarget.value) })}>
                    <option value='user'>{app.t('normalUser', '普通用户')}</option>
                    <option value='auditor'>{app.t('auditor', '审计员')}</option>
                    <option value='admin'>{app.t('administrator', '管理员')}</option>
                    {roleItems.map((item) => (
                      <option key={item.id} value={item.name}>{item.name}</option>
                    ))}
                  </Select>
                </Field>
              ) : null}
              {isUser || (isCredential && form.type !== 'ssh_key') ? (
                <Field label={app.t('password', '密码')}><Input type='password' value={form.password} onChange={(event) => onChange({ password: event.currentTarget.value })} /></Field>
              ) : null}
              {isCredential && form.type === 'ssh_key' ? (
                <>
                  <Field label='Private key'><Textarea value={form.private_key} onChange={(event) => onChange({ private_key: event.currentTarget.value })} /></Field>
                  <Field label='Passphrase'><Input type='password' value={form.passphrase} onChange={(event) => onChange({ passphrase: event.currentTarget.value })} /></Field>
                </>
              ) : null}
              <Field label={app.t('group')}><Input value={form.group} onChange={(event) => onChange({ group: event.currentTarget.value })} /></Field>
              <Field label={app.t('owner', '归属用户/部门')}><Input value={form.owner_id} onChange={(event) => onChange({ owner_id: event.currentTarget.value })} /></Field>
              <Field label={app.t('target', '目标资源')}><Input value={form.target_id} onChange={(event) => onChange({ target_id: event.currentTarget.value })} /></Field>
              <Field label={isDepartment ? app.t('parentDepartment', '上级部门') : app.t('parent', '上级/分组')}>
                {isDepartment ? (
                  <Select value={form.parent_id} onChange={(event) => onChange({ parent_id: event.currentTarget.value })}>
                    <option value=''>{app.t('none', '无')}</option>
                    {items.filter((item) => item.id !== editingId).map((item) => (
                      <option key={item.id} value={item.id}>{metadataText(item.metadata?.path) || item.name}</option>
                    ))}
                  </Select>
                ) : (
                  <Input value={form.parent_id} onChange={(event) => onChange({ parent_id: event.currentTarget.value })} />
                )}
              </Field>
              <Field label={app.t('tags', '标签')}><Input placeholder='prod,linux,web' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
            </>
          )}
        </div>
        {isRole ? (
          <div className='grid gap-4 rounded-lg border border-border bg-background/70 p-3'>
            <Field label={app.t('apiPermissions', 'API 权限')}>
              <Textarea
                value={roleAPIText(form.metadata)}
                onChange={(event) => onChange({ metadata: metadataWithList(form.metadata, 'api_permissions', splitLines(event.currentTarget.value)) })}
                placeholder={'GET /api/admin/assets\nPOST /api/access/ssh/*\naudit:read'}
              />
            </Field>
            <div className='grid gap-2'>
              <div className='text-sm font-medium'>{app.t('menuPermissions', '菜单权限')}</div>
              <div className='grid max-h-60 gap-2 overflow-auto rounded-lg border border-border bg-muted/20 p-2 sm:grid-cols-2 lg:grid-cols-3'>
                {platformPages.map((page) => {
                  const selected = roleMenuPermissions(form.metadata).includes(page.collection) || roleMenuPermissions(form.metadata).includes(page.route)
                  return (
                    <label key={page.route} className='flex min-w-0 items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-background'>
                      <input
                        type='checkbox'
                        className='size-4 accent-primary'
                        checked={selected}
                        onChange={() => onChange({ metadata: metadataWithList(form.metadata, 'menu_permissions', toggleString(roleMenuPermissions(form.metadata), page.collection)) })}
                      />
                      <span className='truncate'>{platformLabel(page, app.locale)}</span>
                    </label>
                  )
                })}
              </div>
            </div>
          </div>
        ) : null}
        <Field label={app.t('details')}><Textarea value={form.description} onChange={(event) => onChange({ description: event.currentTarget.value })} /></Field>
        <Field label='Metadata JSON'><Textarea value={form.metadata} onChange={(event) => onChange({ metadata: event.currentTarget.value })} /></Field>
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

function defaultPlatformType(collection: string) {
  if (collection === 'credentials') return 'ssh_password'
  if (collection === 'users') return 'local'
  if (collection === 'departments') return 'department'
  if (collection === 'roles') return 'custom'
  if (collection === 'command_filters') return 'deny'
  if (collection === 'command_snippets') return 'public'
  if (collection === 'authorization_strategies') return 'file'
  return ''
}

function defaultPlatformPermissions(collection: string): Record<string, boolean> {
  if (collection !== 'authorization_strategies') return {}
  return { upload: true, download: true, edit: true, delete: false, rename: true, copy: true, paste: true }
}

function defaultPlatformMetadata(collection: string) {
  if (collection === 'command_filters') return JSON.stringify({ risk: 'high' }, null, 2)
  if (collection === 'command_snippets') return JSON.stringify({ command: '', append_newline: false }, null, 2)
  if (collection === 'authorization_strategies') return JSON.stringify({ path_prefix: '' }, null, 2)
  return ''
}

function formFromPlatformItem(item: PlatformItem): PlatformFormState {
  return {
    name: item.name || '',
    type: item.type || '',
    status: item.status || 'enabled',
    protocol: item.protocol || '',
    host: item.host || '',
    port: item.port ? String(item.port) : '',
    username: item.username || '',
    password: '',
    private_key: '',
    passphrase: '',
    group: item.group || '',
    owner_id: item.owner_id || '',
    parent_id: item.parent_id || '',
    target_id: item.target_id || '',
    tags: item.tags?.join(',') || '',
    permissions: item.permissions || {},
    metadata: item.metadata ? JSON.stringify(item.metadata, null, 2) : '',
    description: item.description || '',
  }
}

function platformRequestFromForm(form: PlatformFormState) {
  let metadata: Record<string, unknown> | undefined
  if (form.metadata.trim()) {
    metadata = JSON.parse(form.metadata)
  }
  return {
    name: form.name,
    type: form.type,
    status: form.status,
    protocol: form.protocol || undefined,
    host: form.host,
    port: form.port ? Number(form.port) : 0,
    username: form.username,
    password: form.password || undefined,
    private_key: form.private_key || undefined,
    passphrase: form.passphrase || undefined,
    group: form.group,
    owner_id: form.owner_id,
    parent_id: form.parent_id,
    target_id: form.target_id,
    tags: form.tags.split(',').map((tag) => tag.trim()).filter(Boolean),
    permissions: form.permissions,
    metadata,
    description: form.description,
  }
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
  const [databaseQueryItem, setDatabaseQueryItem] = useState<PlatformItem | null>(null)
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
      <AccessSection title='Web资产' items={webAssets} protocol='http' />
      <AccessSection title='数据库资产' items={databaseAssets} protocol='database' onDatabaseQuery={setDatabaseQueryItem} />
      {databaseQueryItem ? (
        <SQLExecuteDialog
          item={databaseQueryItem}
          endpoint={`/api/access/database/${databaseQueryItem.id}/query`}
          workOrderEndpoint={`/api/access/database/${databaseQueryItem.id}/work-orders`}
          initialSQL={stringValue(databaseQueryItem.metadata?.sql) || 'SELECT name FROM sqlite_master WHERE type = "table";'}
          successMessage='SQL 已执行'
          workOrderMessage='SQL 工单已提交'
          description='在授权数据库资产上执行 SQL，结果会写入 SQL 日志；SELECT 查询按资产配置的 row_limit 返回。'
          onClose={() => setDatabaseQueryItem(null)}
        />
      ) : null}
    </div>
  )
}

function AccessSection({
  title,
  items,
  protocol,
  onDatabaseQuery,
}: {
  title: string
  items: PlatformItem[]
  protocol?: string
  onDatabaseQuery?: (item: PlatformItem) => void
}) {
  const app = useApp()
  const connect = async (item: PlatformItem) => {
    const accessProtocol = (protocol || item.protocol || 'ssh') as Protocol
    if (accessProtocol === 'http') {
      window.open(`/api/access/http/${item.id}/proxy/`, '_blank', 'noopener,noreferrer')
      return
    }
    if (accessProtocol === 'database') {
      onDatabaseQuery?.(item)
      return
    }
    try {
      const body = accessProtocol === 'rdp' || accessProtocol === 'vnc'
        ? JSON.stringify({
          width: Math.max(1024, window.innerWidth),
          height: Math.max(680, window.innerHeight - 52),
          dpi: 96,
          recording_enabled: true,
        })
        : '{}'
      const session = await apiRequest<ConnectionSession>(`/api/access/${accessProtocol}/${item.id}`, { method: 'POST', body })
      if (accessProtocol === 'rdp' || accessProtocol === 'vnc') {
        app.setWorkspace({ type: accessProtocol, session, status: 'connecting' })
      } else {
        await app.refresh(true)
        app.showToast('已创建接入会话')
      }
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

function BackupsPage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const label = platformLabel(config, app.locale)
  const description = platformDescription(config, app.locale)
  const Icon = config.icon
  const [items, setItems] = useState<BackupInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [creating, setCreating] = useState(false)
  const [restoring, setRestoring] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [validation, setValidation] = useState<Record<string, unknown> | null>(null)

  const load = async () => {
    setLoading(true)
    try {
      const data = await apiRequest<{ items: BackupInfo[] }>(config.apiPath || '/api/admin/backups')
      setItems(data.items || [])
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [config.apiPath])

  const createBackup = async () => {
    setCreating(true)
    try {
      await apiRequest(config.apiPath || '/api/admin/backups', { method: 'POST', body: '{}' })
      await load()
      app.showToast('备份已创建')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setCreating(false)
    }
  }

  const validateUpload = async () => {
    if (!uploadFile) return
    setRestoring(true)
    try {
      setValidation(await submitBackupFile(uploadFile, true))
      app.showToast('备份校验通过')
    } catch (error) {
      app.handleApiError(error)
      setValidation(null)
    } finally {
      setRestoring(false)
    }
  }

  const restoreUpload = async () => {
    if (!uploadFile) return
    if (!window.confirm('恢复会覆盖当前系统数据，并在恢复前自动创建一份当前备份。继续?')) return
    setRestoring(true)
    try {
      const result = await submitBackupFile(uploadFile, false)
      setValidation(result)
      app.showToast('恢复完成，请重新登录')
      window.setTimeout(() => window.location.assign('/login'), 800)
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setRestoring(false)
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
              <Button variant='outline' onClick={() => void load()} disabled={loading}>
                <RefreshCw className={cn('size-4', loading && 'animate-spin')} />
                刷新
              </Button>
              <Button variant='primary' onClick={() => void createBackup()} disabled={creating}>
                <Save className='size-4' />
                {creating ? '备份中' : '立即备份'}
              </Button>
            </div>
          </CardHeader>
          <CardContent className='grid gap-5'>
            <section className='grid gap-3 rounded-xl border border-border bg-background/60 p-4'>
              <div>
                <h3 className='text-sm font-semibold'>上传恢复</h3>
                <p className='mt-1 text-xs leading-5 text-muted-foreground'>上传系统生成的备份 zip。执行恢复前会自动创建一份当前数据备份，恢复后需要重新登录。</p>
              </div>
              <div className='grid gap-3 md:grid-cols-[minmax(0,1fr)_auto_auto]'>
                <Input type='file' accept='.zip,application/zip' onChange={(event) => {
                  setUploadFile(event.currentTarget.files?.[0] || null)
                  setValidation(null)
                }} />
                <Button variant='outline' onClick={() => void validateUpload()} disabled={!uploadFile || restoring}>
                  <FileSearch className='size-4' />
                  校验
                </Button>
                <Button variant='destructive' onClick={() => void restoreUpload()} disabled={!uploadFile || restoring}>
                  <Upload className='size-4' />
                  {restoring ? '处理中' : '恢复'}
                </Button>
              </div>
              {validation ? (
                <pre className='max-h-56 overflow-auto rounded-lg bg-muted p-3 text-xs'>{JSON.stringify(validation, null, 2)}</pre>
              ) : null}
            </section>
            <div className='grid gap-3'>
              {items.length ? items.map((item) => (
                <article key={item.name} className='grid gap-3 rounded-xl border border-border bg-background/60 p-4 md:grid-cols-[minmax(0,1fr)_auto] md:items-center'>
                  <div className='min-w-0'>
                    <div className='flex flex-wrap items-center gap-2'>
                      <h3 className='truncate text-sm font-semibold'>{item.name}</h3>
                      <Badge tone='neutral'>{formatBytesValue(item.size)}</Badge>
                    </div>
                    <p className='mt-1 text-xs text-muted-foreground'>{formatDate(item.modified_at)} · {(item.files || []).join(', ') || 'manifest only'}</p>
                  </div>
                  <Button variant='outline' onClick={() => void downloadResponse(`/api/admin/backups/${encodeURIComponent(item.name)}/download`, item.name)}>
                    <Download className='size-4' />
                    下载
                  </Button>
                </article>
              )) : (
                <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>暂无备份。点击“立即备份”生成第一份快照。</div>
              )}
            </div>
          </CardContent>
        </Card>
      </CardStaggerItem>
    </CardStaggerContainer>
  )
}

async function submitBackupFile(file: File, dryRun: boolean) {
  const form = new FormData()
  form.set('file', file)
  if (dryRun) form.set('dry_run', 'true')
  const response = await fetch(`/api/admin/backups/restore${dryRun ? '?dry_run=1' : ''}`, {
    method: 'POST',
    credentials: 'same-origin',
    body: form,
  })
  const payload = await response.json().catch(() => ({})) as Record<string, unknown> & { error?: string }
  if (!response.ok) {
    throw new ApiError(payload.error || response.statusText, response.status, Boolean(payload.setup_required))
  }
  return payload
}

function AccessStatsPage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const label = platformLabel(config, app.locale)
  const description = platformDescription(config, app.locale)
  const Icon = config.icon
  const [items, setItems] = useState<PlatformItem[]>([])
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const data = await apiRequest<{ items: PlatformItem[] }>(config.apiPath || '/api/admin/audit/access-stats')
      setItems(data.items || [])
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [config.apiPath])

  const summary = items.find((item) => item.type === 'summary')
  const summaryMetadata = summary?.metadata || {}
  const metrics = [
    { label: 'PV', value: formatNumberValue(summaryMetadata.pv) },
    { label: 'UV', value: formatNumberValue(summaryMetadata.uv) },
    { label: '独立 IP', value: formatNumberValue(summaryMetadata.unique_ips) },
    { label: '请求数', value: formatNumberValue(summaryMetadata.request_count) },
    { label: '流量', value: formatBytesValue(summaryMetadata.traffic_bytes) },
    { label: '平均耗时', value: `${formatNumberValue(summaryMetadata.average_duration_ms)} ms` },
    { label: '错误率', value: formatPercentValue(summaryMetadata.error_rate) },
    { label: '错误数', value: formatNumberValue(summaryMetadata.error_count) },
  ]
  const sections = [
    { type: 'top_pages', title: '热门页面' },
    { type: 'referrers', title: '来源统计' },
    { type: 'assets', title: '资产排行' },
    { type: 'status_codes', title: '状态码' },
    { type: 'methods', title: '请求方法' },
  ]

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
            <Button variant='outline' onClick={() => void load()} disabled={loading}>
              <RefreshCw className={cn('size-4', loading && 'animate-spin')} />
              刷新
            </Button>
          </CardHeader>
          <CardContent className='grid gap-5'>
            <div className='grid gap-3 sm:grid-cols-2 xl:grid-cols-4'>
              {metrics.map((metric) => (
                <div key={metric.label} className='rounded-xl border border-border bg-background/60 p-4'>
                  <div className='text-xs font-medium text-muted-foreground'>{metric.label}</div>
                  <div className='mt-2 truncate font-mono text-xl font-semibold'>{metric.value}</div>
                </div>
              ))}
            </div>
            <div className='grid gap-3 lg:grid-cols-2'>
              {sections.map((section) => (
                <AccessStatsRank key={section.type} title={section.title} item={items.find((entry) => entry.type === section.type)} />
              ))}
            </div>
          </CardContent>
        </Card>
      </CardStaggerItem>
    </CardStaggerContainer>
  )
}

function AccessStatsRank({ title, item }: { title: string; item?: PlatformItem }) {
  const entries = objectArrayValue(item?.metadata?.entries)
  return (
    <section className='rounded-xl border border-border bg-background/60 p-4'>
      <div className='flex items-center justify-between gap-3'>
        <h3 className='text-sm font-semibold'>{title}</h3>
        <Badge tone='neutral'>{entries.length}</Badge>
      </div>
      <div className='mt-3 grid gap-2'>
        {entries.length ? entries.map((entry, index) => (
          <div key={`${String(entry.key)}-${index}`} className='grid grid-cols-[minmax(0,1fr)_auto] items-center gap-3 rounded-lg bg-muted/60 px-3 py-2 text-sm'>
            <span className='truncate font-mono text-xs'>{String(entry.key || '-')}</span>
            <strong className='font-mono text-xs'>{formatNumberValue(entry.value)}</strong>
          </div>
        )) : (
          <div className='rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground'>暂无统计数据。</div>
        )}
      </div>
    </section>
  )
}

function splitCSV(value: string) {
  return value.split(',').map((item) => item.trim()).filter(Boolean)
}

function splitLines(value: string) {
  return value.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean)
}

function stringValue(value: unknown) {
  return typeof value === 'string' ? value : ''
}

function metadataText(value: unknown) {
  if (typeof value === 'string') return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  return ''
}

function metadataNumber(value: unknown) {
  return numberValue(value)
}

function departmentLevel(item: PlatformItem) {
  return Math.max(0, metadataNumber(item.metadata?.level))
}

function metadataBool(value: unknown) {
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  if (typeof value === 'string') return ['true', '1', 'yes', 'enabled', 'online'].includes(value.trim().toLowerCase())
  return false
}

function userOnline(item: PlatformItem) {
  return metadataBool(item.metadata?.online)
}

function stringArrayValue(value: unknown) {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function metadataObject(value: string): Record<string, unknown> {
  if (!value.trim()) return {}
  try {
    const parsed = JSON.parse(value) as unknown
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}
  } catch {
    return {}
  }
}

function metadataFormText(metadata: string, key: string) {
  const value = metadataObject(metadata)[key]
  if (Array.isArray(value)) return value.map((item) => metadataText(item)).filter(Boolean).join('\n')
  return metadataText(value)
}

function metadataBoolFromForm(metadata: string, key: string) {
  return metadataBool(metadataObject(metadata)[key])
}

function permissionSummary(permissions: Record<string, boolean> | undefined) {
  const source = permissions || {}
  const enabled = filePermissionActions.filter((action) => source[action.key]).map((action) => action.key)
  const disabled = filePermissionActions.filter((action) => Object.prototype.hasOwnProperty.call(source, action.key) && !source[action.key]).map((action) => `-${action.key}`)
  return [...enabled, ...disabled].join(' ') || '-'
}

function metadataWithValue(metadata: string, key: string, value: unknown) {
  const next = metadataObject(metadata)
  if (value === '' || value === undefined || value === null) {
    delete next[key]
  } else {
    next[key] = value
  }
  return JSON.stringify(next, null, 2)
}

function metadataWithList(metadata: string, key: string, value: string[]) {
  return metadataWithValue(metadata, key, value)
}

function metadataStringListFromForm(metadata: string, key: string) {
  const value = metadataObject(metadata)[key]
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string')
  if (typeof value === 'string') return splitLines(value)
  return []
}

function roleValue(metadata: string) {
  const value = metadataObject(metadata).role
  return typeof value === 'string' && value.trim() ? value.trim() : 'user'
}

function roleAPIText(metadata: string) {
  return metadataStringListFromForm(metadata, 'api_permissions').join('\n')
}

function roleMenuPermissions(metadata: string) {
  return metadataStringListFromForm(metadata, 'menu_permissions')
}

function toggleString(items: string[], value: string) {
  return items.includes(value) ? items.filter((item) => item !== value) : [...items, value]
}

function objectArrayValue(value: unknown) {
  return Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => Boolean(item) && typeof item === 'object' && !Array.isArray(item)) : []
}

function numberValue(value: unknown) {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string') {
    const parsed = Number(value)
    return Number.isFinite(parsed) ? parsed : 0
  }
  return 0
}

function formatNumberValue(value: unknown) {
  return new Intl.NumberFormat().format(numberValue(value))
}

function formatBytesValue(value: unknown) {
  const bytes = numberValue(value)
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let current = bytes / 1024
  let unitIndex = 0
  while (current >= 1024 && unitIndex < units.length - 1) {
    current /= 1024
    unitIndex += 1
  }
  return `${current.toFixed(current >= 10 ? 1 : 2)} ${units[unitIndex]}`
}

function formatPercentValue(value: unknown) {
  return `${(numberValue(value) * 100).toFixed(1)}%`
}

function formatPercentValueFromWhole(value: unknown) {
  return `${numberValue(value).toFixed(1)}%`
}

function itemHasRecording(item: PlatformItem) {
  return Boolean(stringValue(item.metadata?.recording_path))
}

function joinStoragePath(base: string, name: string) {
  const cleanBase = base === '.' ? '' : base.replace(/^\/+|\/+$/g, '')
  const cleanName = name.replace(/^\/+/g, '')
  return [cleanBase, cleanName].filter(Boolean).join('/') || '.'
}

function parentStoragePath(value: string) {
  const parts = value.split('/').filter(Boolean)
  if (parts.length <= 1) return '.'
  return parts.slice(0, -1).join('/')
}

function downloadText(filename: string, content: string, type: string) {
  const blob = new Blob([content], { type })
  downloadBlob(filename, blob)
}

async function downloadResponse(path: string, filename: string) {
  const response = await fetch(path, { credentials: 'same-origin' })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string }
    throw new Error(payload.error || response.statusText)
  }
  downloadBlob(filename, await response.blob())
}

function downloadBlob(filename: string, blob: Blob) {
  const href = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = href
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(href)
}

function statusTone(status?: string) {
  const value = (status || '').toLowerCase()
  if (['active', 'enabled', 'success', 'normal', 'encrypted'].includes(value)) return 'success' as const
  if (['pending', 'disabled', 'offline'].includes(value)) return 'warning' as const
  if (['failed', 'locked', 'denied'].includes(value)) return 'danger' as const
  return 'neutral' as const
}

function riskTone(risk?: string) {
  const value = (risk || '').toLowerCase()
  if (['critical', 'high'].includes(value)) return 'danger' as const
  if (['medium', 'warning'].includes(value)) return 'warning' as const
  if (['low', 'normal'].includes(value)) return 'success' as const
  return 'neutral' as const
}
