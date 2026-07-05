import type { ColumnDef } from '@tanstack/react-table'
import { Link } from '@tanstack/react-router'
import { ArrowUpRight, Download, FileDown, FileSearch, FolderPlus, Pencil, Play, Plus, RefreshCw, Save, Trash2, Upload } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

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
  password: string
  group: string
  owner_id: string
  parent_id: string
  target_id: string
  tags: string
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
  group: '',
  owner_id: '',
  parent_id: '',
  target_id: '',
  tags: '',
  metadata: '',
  description: '',
}

type ResourceOperation =
  | { type: 'asset-import' }
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

export function PlatformPage({ config }: { config: PlatformPageConfig }) {
  if (config.kind === 'tools') return <ToolsPage config={config} />
  if (config.kind === 'monitor') return <MonitoringPage config={config} />
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
    setForm(initialForm)
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
              getSearchText={(item) => [item.name, item.type, item.status, item.protocol, item.host, item.group, item.username, item.description, item.tags?.join(' ')].filter(Boolean).join(' ')}
            />
          </CardContent>
        </Card>
      </CardStaggerItem>
      <PlatformItemDialog
        title={`${editing ? app.t('edit', '编辑') : app.t('new', '新建')} ${label}`}
        description={description}
        open={formOpen}
        saving={saving}
        form={form}
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

function SQLExecuteDialog({ item, onClose }: { item: PlatformItem; onClose: () => void }) {
  const app = useApp()
  const [sql, setSQL] = useState(stringValue(item.metadata?.sql))
  const [result, setResult] = useState<PlatformItem | null>(null)
  const [running, setRunning] = useState(false)

  const execute = async () => {
    setRunning(true)
    try {
      const data = await apiRequest<PlatformItem>(`/api/admin/sql-work-orders/${item.id}/execute`, {
        method: 'POST',
        body: JSON.stringify({ sql }),
      })
      setResult(data)
      await app.refresh(true)
      app.showToast('SQL 工单已执行')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setRunning(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} 执行`} description='执行结果会写入 SQL 日志；SELECT 查询最多展示前 100 行。'>
      <div className='grid gap-4'>
        <Field label='SQL'><Textarea className='min-h-44 font-mono text-xs' value={sql} onChange={(event) => setSQL(event.currentTarget.value)} /></Field>
        {result ? (
          <div className='rounded-xl border border-border bg-background/60 p-3'>
            <div className='flex items-center justify-between gap-3 text-sm'>
              <strong>{result.description || result.name}</strong>
              <Badge tone={statusTone(result.status)}>{result.status}</Badge>
            </div>
            <pre className='mt-3 max-h-80 overflow-auto rounded-lg bg-muted p-2 text-xs'>{JSON.stringify(result.metadata || {}, null, 2)}</pre>
          </div>
        ) : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>关闭</Button>
          <Button variant='primary' onClick={() => void execute()} disabled={running || !sql.trim()}>
            <Play className='size-4' />
            {running ? '执行中' : '执行'}
          </Button>
        </div>
      </div>
    </DialogShell>
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
          {title.includes('用户') || title.includes('Users') ? (
            <Field label={app.t('password', '密码')}><Input type='password' value={form.password} onChange={(event) => onChange({ password: event.currentTarget.value })} /></Field>
          ) : null}
          <Field label={app.t('group')}><Input value={form.group} onChange={(event) => onChange({ group: event.currentTarget.value })} /></Field>
          <Field label={app.t('owner', '归属用户/部门')}><Input value={form.owner_id} onChange={(event) => onChange({ owner_id: event.currentTarget.value })} /></Field>
          <Field label={app.t('target', '目标资源')}><Input value={form.target_id} onChange={(event) => onChange({ target_id: event.currentTarget.value })} /></Field>
          <Field label={app.t('parent', '上级/分组')}><Input value={form.parent_id} onChange={(event) => onChange({ parent_id: event.currentTarget.value })} /></Field>
          <Field label={app.t('tags', '标签')}><Input placeholder='prod,linux,web' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
        </div>
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
    group: item.group || '',
    owner_id: item.owner_id || '',
    parent_id: item.parent_id || '',
    target_id: item.target_id || '',
    tags: item.tags?.join(',') || '',
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
    group: form.group,
    owner_id: form.owner_id,
    parent_id: form.parent_id,
    target_id: form.target_id,
    tags: form.tags.split(',').map((tag) => tag.trim()).filter(Boolean),
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

function splitCSV(value: string) {
  return value.split(',').map((item) => item.trim()).filter(Boolean)
}

function stringValue(value: unknown) {
  return typeof value === 'string' ? value : ''
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
