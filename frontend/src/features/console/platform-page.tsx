import type { ColumnDef } from '@tanstack/react-table'
import { useQuery } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { ArrowUpRight, ChevronDown, ChevronRight, Copy, Download, FileDown, FileSearch, Film, FolderPlus, Loader2, MoveRight, Pause, Pencil, Play, Plus, RefreshCw, RotateCcw, Save, ShieldCheck, TerminalSquare, Trash2, Upload } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { isAccessMFARequiredError, useAccessMFADialog, type RequestAccessMFACode } from '@/features/access/access-mfa'
import { DataTable } from '@/components/data-table/data-table'
import { CardStaggerContainer, CardStaggerItem } from '@/components/page-transition'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useConfirmDialog } from '@/components/ui/confirm-dialog'
import { DialogShell } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/field'
import { ApiError, apiRequest } from '@/lib/api'
import { copyText } from '@/lib/clipboard'
import { platformDescription, platformLabel, platformPageByRoute, platformPages, type PlatformPageConfig } from '@/lib/platform'
import { canUseAPI, canViewPlatformPage } from '@/lib/rbac'
import { cn, formatDate } from '@/lib/utils'
import type { ConnectionSession, PlatformItem, Protocol, PublicConfig } from '@/types'

interface PlatformFormState {
  name: string
  type: string
  status: string
  protocol: string
  host: string
  port: string
  username: string
  password: string
  oidcClientSecretSet: boolean
  oidcClientSecretClear: boolean
  databaseDSNSet: boolean
  databaseDSNClear: boolean
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

interface AccessAssetsResponse {
  text?: PlatformItem[]
  desktop?: PlatformItem[]
  web?: PlatformItem[]
  database?: PlatformItem[]
  authorized?: PlatformItem[]
  authorized_assets?: PlatformItem[]
  authorized_web_assets?: PlatformItem[]
  authorized_database_assets?: PlatformItem[]
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
  oidcClientSecretSet: false,
  oidcClientSecretClear: false,
  databaseDSNSet: false,
  databaseDSNClear: false,
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
  | { type: 'user-import' }
  | { type: 'bulk-authorize'; collection: string; items: PlatformItem[] }
  | { type: 'agent-token'; item: PlatformItem }
  | { type: 'gateway-status'; collection: 'agent_gateways' | 'gateway_groups'; item: PlatformItem }
  | { type: 'certificate-create' }
  | { type: 'certificate-upload' }
  | { type: 'certificate-acme' }
  | { type: 'certificate-dns-provider' }
  | { type: 'certificate-logs'; item: PlatformItem }
  | { type: 'certificate-mtls'; item: PlatformItem }
  | { type: 'recording-playback'; item: PlatformItem }
  | { type: 'storage-files'; item: PlatformItem }
  | { type: 'task-logs'; item: PlatformItem }
  | { type: 'sql-execute'; item: PlatformItem }
  | { type: 'sql-decision'; item: PlatformItem; decision: 'approve' | 'reject' }
  | { type: 'command-execute'; item: PlatformItem }
  | { type: 'command-decision'; item: PlatformItem; decision: 'approve' | 'reject' }

type CanUsePath = (method: string, path: string) => boolean

interface StorageEntry {
  name: string
  path: string
  is_dir: boolean
  size: number
  modified: string
}

interface StorageUsage {
  bytes: number
  files: number
  dirs: number
  limit_bytes?: number
  available_bytes?: number
  used?: string
  limit?: string
  checked_at?: string
}

interface RecordingTranscodeStatus {
  available: boolean
  detail?: string
  status?: 'queued' | 'processing' | 'completed' | 'failed'
  error?: string
  video_size?: number
  video_url?: string
  started_at?: string
  finished_at?: string
}

interface AgentGatewayStatusResponse {
  items?: PlatformItem[]
  online?: number
  offline?: number
  checked_at?: string
}

interface GatewayGroupMemberStatus {
  id: string
  name: string
  collection: string
  type?: string
  status: string
  online: boolean
  host?: string
  port?: number
  tags?: string[]
  latency_ms?: number
  active_sessions?: number
  capabilities?: string[]
  last_heartbeat_at?: string
  metadata?: Record<string, unknown>
}

interface GatewayGroupRuntimeStatus {
  id: string
  name: string
  type: string
  status: string
  selection_mode: string
  member_ids?: string[]
  required_labels?: string[]
  required_capabilities?: string[]
  members?: GatewayGroupMemberStatus[]
  online?: number
  offline?: number
  selected_gateway_id?: string
  selected_gateway?: GatewayGroupMemberStatus
  checked_at?: string
}

interface GatewayGroupStatusResponse {
  items?: GatewayGroupRuntimeStatus[]
  checked_at?: string
}

interface DepartmentTreeNode {
  item: PlatformItem
  children: DepartmentTreeNode[]
}

interface AssetGroupTreeNode {
  item: PlatformItem
  children: AssetGroupTreeNode[]
  directAssetCount: number
  totalAssetCount: number
  assetIDs: Set<string>
}

interface BackupInfo {
  name: string
  size: number
  modified_at: string
  manifest?: Record<string, unknown>
  files?: string[]
}

type ImportSummary = Record<string, number>

const assetImportJSONSample = JSON.stringify({
  update_existing: false,
  items: [
    {
      name: 'linux-prod-01',
      type: 'linux',
      status: 'active',
      protocol: 'ssh',
      host: '192.0.2.10',
      port: 22,
      group: 'production',
      tags: ['linux', 'ssh'],
      metadata: { credential_id: 'credential-id' },
    },
  ],
}, null, 2)

const assetImportCSVSample = [
  'name,type,status,protocol,host,port,group,tags,credential_id,gateway_group_id,metadata_json',
  'linux-prod-01,linux,active,ssh,192.0.2.10,22,production,"linux,ssh",credential-id,,"{""import_note"":""csv""}"',
].join('\n')

const userImportJSONSample = JSON.stringify({
  update_existing: false,
  items: [
    {
      name: 'operator',
      type: 'local',
      status: 'enabled',
      password: 'change-me-123',
      metadata: { role: 'user' },
    },
  ],
}, null, 2)

const userImportCSVSample = [
  'name,type,status,password,role,group,tags',
  'operator,local,enabled,change-me-123,user,ops,"operator,import"',
].join('\n')

interface SMTPIntegrationForm {
  host: string
  port: string
  security: 'none' | 'starttls' | 'tls'
  serverName: string
  insecureSkipVerify: boolean
  username: string
  password: string
  passwordSet: boolean
  passwordClear: boolean
  from: string
  to: string
  testTo: string
  notificationsEnabled: boolean
  notifySecurity: boolean
  notifyTasks: boolean
  notifyGateways: boolean
  notifyOperations: boolean
  sendExistingNotifications: boolean
  llmProvider: string
  llmBaseUrl: string
  llmModel: string
  llmApiKey: string
  llmApiKeySet: boolean
  llmApiKeyClear: boolean
}

interface DesktopAccessForm {
  width: string
  height: string
  dpi: string
  colorDepth: string
  resizeMethod: string
  recordingEnabled: boolean
  clipboardEnabled: boolean
  fileTransferEnabled: boolean
  sshFileTransferEnabled: boolean
  ignoreCert: boolean
  readOnly: boolean
  watermarkEnabled: boolean
  watermarkText: string
  watermarkColor: string
  watermarkFontSize: string
  accessMfaEnabled: boolean
  accessMfaValidMinutes: string
}

interface ProxyServicesForm {
  sshEnabled: boolean
  sshListenAddress: string
  sshDisablePasswordAuth: boolean
  sshForwardAllowlist: string
  rdpEnabled: boolean
  rdpListenAddress: string
  rdpForwardAllowlist: string
  databaseEnabled: boolean
  databaseListenAddress: string
  databaseForwardAllowlist: string
  proxyPrivateKey: string
  proxyPrivateKeySet: boolean
  proxyPrivateKeyClear: boolean
}

interface ProxyServicesStatus {
  ssh_gateway?: Record<string, unknown>
  rdp_proxy?: Record<string, unknown>
  database_proxy?: Record<string, unknown>
}

interface ProxyRouteStatus {
  listen_address: string
  target: string
}

interface BrandingForm {
  siteName: string
  logoUrl: string
  assetLogoUrl: string
  githubUrl: string
  copyright: string
  icpNumber: string
  aboutTitle: string
  aboutDescription: string
  aboutBody: string
  footerText: string
  navLinks: string
}

interface SSHExecResult {
  session_id: string
  command: string
  stdout: string
  stderr: string
  exit_code: number
  status: string
  duration_ms: number
  action: string
  risk: string
  blocked: boolean
  error?: string
}

interface PingToolResult {
  seq: number
  mode: string
  target: string
  address?: string
  status: string
  latency?: number
  latency_ms?: number
  detail?: string
}

interface PingToolResponse {
  target: string
  mode: string
  count: number
  results: PingToolResult[]
  summary?: {
    ok?: number
    failed?: number
  }
}

export function PlatformPage({ config }: { config: PlatformPageConfig }) {
  if (config.kind === 'tools') return <ToolsPage config={config} />
  if (config.kind === 'monitor') return <MonitoringPage config={config} />
  if (config.kind === 'backups') return <BackupsPage config={config} />
  if (config.kind === 'settings') return <PlatformSettingsPage config={config} />
  if (config.collection === 'access_stats') return <AccessStatsPage config={config} />
  return <PlatformTablePage config={config} />
}

export function PlatformTablePage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const label = platformLabel(config, app.locale)
  const description = platformDescription(config, app.locale)
  const Icon = config.icon
  const rows = app.data.platform?.[config.collection] || []
  const apiPath = config.apiPath || `/api/admin/${config.collection}`
  const role = app.auth?.role
  const apiPermissions = app.auth?.api_permissions || []
  const canUsePath: CanUsePath = (method, path) => canUseAPI(role, apiPermissions, method, path)
  const auditReadOnly = apiPath.startsWith('/api/admin/audit/')
  const canCreate = !auditReadOnly && canUsePath('POST', apiPath)
  const canEditPath = (path: string) => canUsePath('PATCH', path)
  const canDeletePath = (path: string) => canUsePath('DELETE', path)
  const canEditItem = (item: PlatformItem) => !auditReadOnly && canEditPath(`${apiPath}/${item.id}`)
  const canDeleteItem = (item: PlatformItem) => !auditReadOnly && canDeletePath(`${apiPath}/${item.id}`)
  const [formOpen, setFormOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [editing, setEditing] = useState<PlatformItem | null>(null)
  const [form, setForm] = useState<PlatformFormState>(initialForm)
  const [operation, setOperation] = useState<ResourceOperation | null>(null)
  const [departmentView, setDepartmentView] = useState<'table' | 'tree'>('table')
  const [assetGroupView, setAssetGroupView] = useState<'table' | 'tree'>('table')
  const [selectedIDs, setSelectedIDs] = useState<string[]>([])
  const { requestAccessMFACode, accessMFADialog } = useAccessMFADialog()
  const { confirm, confirmDialog } = useConfirmDialog()
  const selectedRows = useMemo(() => {
    const ids = new Set(selectedIDs)
    return rows.filter((item) => ids.has(item.id))
  }, [rows, selectedIDs])
  const canBulkAuthorize = ['assets', 'web_assets', 'database_assets'].includes(config.collection) &&
    canUsePath('POST', `/api/admin/authorizations/${authorizationBulkRoute(config.collection)}/bulk`)
  const canBulkDelete = Boolean(config.apiPath && !config.apiPath.startsWith('/api/admin/audit/')) &&
    canDeletePath(`${apiPath}/__selected__`)
  const selectionEnabled = canBulkAuthorize || canBulkDelete

  useEffect(() => {
    setSelectedIDs([])
  }, [config.collection])

  useEffect(() => {
    const rowIDs = new Set(rows.map((item) => item.id))
    setSelectedIDs((current) => current.filter((id) => rowIDs.has(id)))
  }, [rows])

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
      ...(config.collection === 'sql_work_orders' ? [
        {
          header: 'SQL / Reason',
          cell: ({ row }) => (
            <div className='grid max-w-96 gap-1'>
              <span className='truncate font-mono text-xs'>{metadataText(row.original.metadata?.sql) || row.original.description || '-'}</span>
              <span className='truncate text-xs text-muted-foreground'>{metadataText(row.original.metadata?.reason) || row.original.description || '-'}</span>
            </div>
          ),
        },
        {
          header: 'Decision',
          cell: ({ row }) => <SQLWorkOrderDecisionSummary item={row.original} />,
        },
        {
          header: 'Execution',
          cell: ({ row }) => <SQLWorkOrderExecutionSummary item={row.original} />,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'command_approvals' ? [
        {
          header: '命令 / 规则',
          cell: ({ row }) => (
            <div className='grid max-w-96 gap-1'>
              <span className='truncate font-mono text-xs'>{metadataText(row.original.metadata?.command) || row.original.name || '-'}</span>
              <span className='truncate text-xs text-muted-foreground'>{metadataText(row.original.metadata?.rule_name) || row.original.description || '-'}</span>
            </div>
          ),
        },
        {
          header: '审批',
          cell: ({ row }) => <CommandApprovalDecisionSummary item={row.original} />,
        },
        {
          header: '执行',
          cell: ({ row }) => <CommandApprovalExecutionSummary item={row.original} />,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'certificates' ? [
        {
          header: app.t('expiresAt', 'Expires at'),
          cell: ({ row }) => <span className='text-xs'>{formatDate(metadataText(row.original.metadata?.expires_at))}</span>,
        },
        {
          header: app.t('certificateFlags', 'Flags'),
          cell: ({ row }) => (
            <div className='flex flex-wrap gap-1'>
              {metadataBool(row.original.metadata?.default) ? <Badge tone='success'>default</Badge> : null}
              {metadataBool(row.original.metadata?.mtls_enabled) ? <Badge tone='warning'>mTLS</Badge> : null}
              {metadataText(row.original.metadata?.acme_order_status) ? <Badge tone='neutral'>{metadataText(row.original.metadata?.acme_order_status)}</Badge> : null}
            </div>
          ),
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'scheduled_tasks' ? [
        {
          header: app.t('schedule', 'Schedule'),
          cell: ({ row }) => <span className='font-mono text-xs'>{scheduledTaskScheduleText(row.original)}</span>,
        },
        {
          header: app.t('lastRun', 'Last run'),
          cell: ({ row }) => (
            <div className='grid gap-0.5 text-xs'>
              <span>{formatDate(metadataText(row.original.metadata?.last_run_at))}</span>
              <span className='text-muted-foreground'>{metadataText(row.original.metadata?.last_run_status) || '-'}</span>
            </div>
          ),
        },
        {
          header: app.t('nextRun', 'Next run'),
          cell: ({ row }) => <span className='text-xs'>{formatDate(metadataText(row.original.metadata?.next_run_at))}</span>,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
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
      ...(config.collection === 'asset_groups' ? [
        {
          header: app.t('protocol'),
          cell: ({ row }) => <Badge tone='neutral'>{row.original.protocol || row.original.type || 'custom'}</Badge>,
        },
        {
          header: app.t('parent', '上级/分组'),
          cell: ({ row }) => <span className='text-xs'>{assetGroupParentName(row.original, app.data.platform?.asset_groups || [])}</span>,
        },
        {
          header: app.t('assets', '资产'),
          cell: ({ row }) => <span className='font-mono text-xs'>{assetGroupAssetCount(row.original, app.data.platform?.assets || [])}</span>,
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
      ...(config.collection === 'oidc_clients' ? [
        {
          header: app.t('oidcClientID', 'Client ID'),
          cell: ({ row }) => <span className='font-mono text-xs'>{metadataText(row.original.metadata?.client_id) || row.original.name}</span>,
        },
        {
          header: app.t('oidcRedirectURIs', 'Redirect URIs'),
          cell: ({ row }) => <span className='line-clamp-2 font-mono text-xs'>{metadataInlineListText(row.original.metadata?.redirect_uris) || '-'}</span>,
        },
        {
          header: app.t('oidcScopes', 'Scopes'),
          cell: ({ row }) => <span className='font-mono text-xs'>{metadataInlineListText(row.original.metadata?.scopes) || 'openid profile email'}</span>,
        },
        {
          header: app.t('oidcAuthMethod', 'Auth method'),
          cell: ({ row }) => <Badge tone='neutral'>{metadataText(row.original.metadata?.token_endpoint_auth_method) || (row.original.type === 'public' ? 'none' : 'client_secret_basic')}</Badge>,
        },
        {
          header: app.t('secretStatus', 'Secret status'),
          cell: ({ row }) => (
            <Badge tone={metadataBool(row.original.metadata?.client_secret_set) ? 'success' : 'neutral'}>
              {metadataBool(row.original.metadata?.client_secret_set) ? app.t('passwordSaved') : app.t('passwordNotSet')}
            </Badge>
          ),
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'authorization_strategies' ? [
        {
          header: app.t('targetResourceType', '目标资源类型'),
          cell: ({ row }) => {
            const resourceType = metadataText(row.original.metadata?.resource_type) || 'storage'
            return <Badge tone='neutral'>{resourceType === 'asset' ? app.t('assetResource', '服务器资产') : app.t('storageResource', '用户存储')}</Badge>
          },
        },
        {
          header: app.t('target', '目标'),
          cell: ({ row }) => {
            const resourceType = metadataText(row.original.metadata?.resource_type) || 'storage'
            const candidates = resourceType === 'asset' ? app.data.platform?.assets || [] : app.data.platform?.storages || []
            const target = candidates.find((item) => item.id === row.original.target_id)
            return <span className='text-xs'>{target?.name || row.original.target_id || (resourceType === 'asset' ? app.t('allAssets', '全部资产') : app.t('allStorages', '全部存储'))}</span>
          },
        },
        {
          header: app.t('permissionMatrix', '权限矩阵'),
          cell: ({ row }) => <span className='font-mono text-xs'>{permissionSummary(row.original.permissions)}</span>,
        },
        {
          header: app.t('pathPrefix', '路径前缀'),
          cell: ({ row }) => <span className='font-mono text-xs'>{metadataText(row.original.metadata?.path_prefix) || '*'}</span>,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(!['asset_groups', 'command_filters', 'command_snippets', 'oidc_clients', 'authorization_strategies'].includes(config.collection) ? [
        {
          header: app.t('address'),
          cell: ({ row }) => {
            const targetURL = config.collection === 'web_assets' ? metadataText(row.original.metadata?.target_url) : ''
            const address = targetURL || (row.original.host ? `${row.original.host}${row.original.port ? `:${row.original.port}` : ''}` : '')
            return address ? <span className='font-mono text-xs'>{address}</span> : '-'
          },
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(config.collection === 'web_assets' ? [
        {
          header: 'mTLS',
          cell: ({ row }) => metadataText(row.original.metadata?.certificate_id) || metadataText(row.original.metadata?.mtls_certificate_id)
            ? <Badge tone='warning'>{metadataText(row.original.metadata?.certificate_id) || metadataText(row.original.metadata?.mtls_certificate_id)}</Badge>
            : <Badge tone='neutral'>{app.t('disabled', 'Disabled')}</Badge>,
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      ...(['assets', 'web_assets', 'database_assets'].includes(config.collection) ? [
        {
          header: app.t('gatewayGroup', '网关分组'),
          cell: ({ row }) => metadataText(row.original.metadata?.gateway_group_id)
            ? <Badge tone='neutral'>{metadataText(row.original.metadata?.gateway_group_id)}</Badge>
            : <span className='text-muted-foreground'>{app.t('directAccess', '直连')}</span>,
        },
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
      ...(config.collection === 'gateway_groups' ? [
        {
          header: app.t('members', '成员'),
          cell: ({ row }) => <span className='font-mono text-xs'>{formatNumberValue(row.original.metadata?.member_count)}</span>,
        },
        {
          header: app.t('online', '在线'),
          cell: ({ row }) => (
            <span className='font-mono text-xs'>
              {formatNumberValue(row.original.metadata?.online_count)} / {formatNumberValue(row.original.metadata?.offline_count)}
            </span>
          ),
        },
        {
          header: app.t('selectedGateway', '当前网关'),
          cell: ({ row }) => {
            const selected = metadataText(row.original.metadata?.selected_gateway_id)
            return selected ? <Badge tone='success'>{selected}</Badge> : <Badge tone='warning'>{app.t('none', '无')}</Badge>
          },
        },
      ] satisfies ColumnDef<PlatformItem>[] : []),
      { header: app.t('group'), accessorFn: (row) => row.group || row.owner_id || row.target_id || '-' },
      { header: app.t('createdAt'), cell: ({ row }) => formatDate(row.original.created_at) },
      {
        id: 'actions',
        header: '',
        cell: ({ row }) => (
          <div className='flex justify-end gap-1.5'>
            <ResourceRowActions config={config} item={row.original} onOperation={setOperation} canUsePath={canUsePath} />
            {canEditItem(row.original) ? (
              <Button size='sm' variant='outline' onClick={() => startEdit(row.original)}>
                <Pencil className='size-3.5' />
                {app.t('edit', '编辑')}
              </Button>
            ) : null}
            {canDeleteItem(row.original) ? (
              <Button size='sm' variant='destructive' onClick={() => void remove(row.original)}>
                <Trash2 className='size-3.5' />
                {app.t('delete', '删除')}
              </Button>
            ) : null}
          </div>
        ),
      },
    ],
    [apiPath, apiPermissions, app, config, role]
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
      protocol: config.collection === 'command_filters' || config.collection === 'asset_groups' ? 'ssh' : config.collection === 'database_assets' ? 'database' : config.collection === 'web_assets' ? 'http' : '',
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
    const confirmed = await confirm({
      title: `${app.t('delete', '删除')} ${item.name}?`,
      description: app.t('confirmDestructiveAction', 'This action cannot be undone.'),
      confirmText: app.t('delete', '删除'),
      destructive: true,
    })
    if (!confirmed) return
    try {
      await apiRequest(`${config.apiPath || `/api/admin/${config.collection}`}/${item.id}`, { method: 'DELETE' })
      await app.refresh(true)
      app.showToast(app.t('deleted', '已删除'))
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const bulkDelete = async () => {
    if (!selectedRows.length || !canBulkDelete) return
    const targets = selectedRows
    const countText = String(targets.length)
    const confirmed = await confirm({
      title: app.t('bulkDeleteConfirmTitle', 'Delete {{count}} selected items?').replace('{{count}}', countText),
      description: app.t('bulkDeleteConfirmDescription', 'This will permanently delete the selected records. This action cannot be undone.').replace('{{count}}', countText),
      confirmText: app.t('bulkDelete', 'Bulk delete'),
      destructive: true,
    })
    if (!confirmed) return
    try {
      for (const item of targets) {
        await apiRequest(`${config.apiPath || `/api/admin/${config.collection}`}/${item.id}`, { method: 'DELETE' })
      }
      setSelectedIDs([])
      await app.refresh(true)
      app.showToast(app.t('bulkDeleteCompleted', '{{count}} item(s) deleted.').replace('{{count}}', countText))
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const selectionActions = selectedRows.length ? (
    <>
      {canBulkAuthorize ? (
        <Button
          size='sm'
          variant='outline'
          onClick={() => setOperation({ type: 'bulk-authorize', collection: config.collection, items: selectedRows })}
        >
          <ShieldCheck className='size-3.5' />
          {app.t('bulkAuthorizeSelected', 'Authorize selected')}
        </Button>
      ) : null}
      {canBulkDelete ? (
        <Button size='sm' variant='destructive' onClick={() => void bulkDelete()}>
          <Trash2 className='size-3.5' />
          {app.t('bulkDelete', 'Bulk delete')}
        </Button>
      ) : null}
    </>
  ) : null

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
              <ResourceHeaderActions config={config} rows={rows} onOperation={setOperation} canUsePath={canUsePath} />
              <Button variant='outline' onClick={() => void app.refresh()}>
                <RefreshCw className='size-4' />
                {app.t('refresh', '刷新')}
              </Button>
              {canCreate ? (
                <Button variant='primary' onClick={startCreate}>
                  <Plus className='size-4' />
                  {app.t('new', '新建')}
                </Button>
              ) : null}
            </div>
          </CardHeader>
          <CardContent>
            {config.collection === 'departments' ? (
              <div className='mb-4 flex flex-wrap gap-2'>
                <Button size='sm' variant={departmentView === 'table' ? 'primary' : 'outline'} onClick={() => setDepartmentView('table')}>
                  {app.t('tableView', '表格视图')}
                </Button>
                <Button size='sm' variant={departmentView === 'tree' ? 'primary' : 'outline'} onClick={() => setDepartmentView('tree')}>
                  {app.t('treeView', '树形视图')}
                </Button>
              </div>
            ) : config.collection === 'asset_groups' ? (
              <div className='mb-4 flex flex-wrap gap-2'>
                <Button size='sm' variant={assetGroupView === 'table' ? 'primary' : 'outline'} onClick={() => setAssetGroupView('table')}>
                  {app.t('tableView', '表格视图')}
                </Button>
                <Button size='sm' variant={assetGroupView === 'tree' ? 'primary' : 'outline'} onClick={() => setAssetGroupView('tree')}>
                  {app.t('treeView', '树形视图')}
                </Button>
              </div>
            ) : null}
            {config.collection === 'departments' && departmentView === 'tree' ? (
              <DepartmentTreeView
                items={rows}
                onEdit={startEdit}
                onDelete={(item) => void remove(item)}
                canEdit={canEditItem}
                canDelete={canDeleteItem}
              />
            ) : config.collection === 'asset_groups' && assetGroupView === 'tree' ? (
              <AssetGroupTreeView
                groups={rows}
                assets={app.data.platform?.assets || []}
                onEdit={startEdit}
                onDelete={(item) => void remove(item)}
                canEdit={canEditItem}
                canDelete={canDeleteItem}
              />
            ) : (
              <DataTable
                columns={columns}
                data={rows}
                emptyTitle={app.t('empty', '暂无数据')}
                emptyBody={description}
                getRowID={(item) => item.id}
                selection={selectionEnabled ? {
                  selectedIDs,
                  onSelectedIDsChange: (ids) => setSelectedIDs(ids),
                  actions: selectionActions,
                } : undefined}
                searchPlaceholder={app.t('filter', '关键词搜索')}
                getSearchText={(item) => [item.name, item.type, item.status, item.protocol, item.host, item.group, item.username, item.description, metadataText(item.metadata?.target_url), metadataText(item.metadata?.certificate_id), metadataText(item.metadata?.mtls_certificate_id), metadataText(item.metadata?.tls_server_name), metadataText(item.metadata?.database), metadataText(item.metadata?.sqlite_path), metadataText(item.metadata?.credential_id), metadataText(item.metadata?.gateway_group_id), metadataText(item.metadata?.gateway_id), metadataText(item.metadata?.pattern), metadataText(item.metadata?.command), metadataText(item.metadata?.risk), metadataText(item.metadata?.path_prefix), permissionSummary(item.permissions), metadataText(item.metadata?.last_login_at), metadataText(item.metadata?.last_login_ip), item.tags?.join(' ')].filter(Boolean).join(' ')}
              />
            )}
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
      <ResourceOperationDialog operation={operation} onOpenChange={setOperation} requestAccessMFACode={requestAccessMFACode} canUsePath={canUsePath} />
      {accessMFADialog}
      {confirmDialog}
    </CardStaggerContainer>
  )
}

function DepartmentTreeView({
  items,
  onEdit,
  onDelete,
  canEdit,
  canDelete,
}: {
  items: PlatformItem[]
  onEdit: (item: PlatformItem) => void
  onDelete: (item: PlatformItem) => void
  canEdit: (item: PlatformItem) => boolean
  canDelete: (item: PlatformItem) => boolean
}) {
  const app = useApp()
  const tree = useMemo(() => buildDepartmentTree(items), [items])

  if (!items.length) {
    return (
      <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>
        {app.t('empty', '暂无数据')}
      </div>
    )
  }

  return (
    <div className='overflow-hidden rounded-xl border border-border bg-background/60'>
      <div className='flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2 text-sm'>
        <div className='font-medium'>{app.t('departmentTree', '部门树')}</div>
        <div className='text-xs text-muted-foreground'>
          {formatNumberValue(items.length)} {app.t('departments', '部门')}
        </div>
      </div>
      <div className='divide-y divide-border'>
        {tree.map((node) => (
          <DepartmentTreeBranch key={node.item.id} node={node} depth={0} onEdit={onEdit} onDelete={onDelete} canEdit={canEdit} canDelete={canDelete} />
        ))}
      </div>
    </div>
  )
}

function DepartmentTreeBranch({
  node,
  depth,
  onEdit,
  onDelete,
  canEdit,
  canDelete,
}: {
  node: DepartmentTreeNode
  depth: number
  onEdit: (item: PlatformItem) => void
  onDelete: (item: PlatformItem) => void
  canEdit: (item: PlatformItem) => boolean
  canDelete: (item: PlatformItem) => boolean
}) {
  const app = useApp()
  const item = node.item
  const directMembers = metadataNumber(item.metadata?.member_count)
  const totalMembers = metadataNumber(item.metadata?.total_member_count)
  const childCount = metadataNumber(item.metadata?.direct_child_count) || node.children.length

  return (
    <div>
      <div className='grid gap-3 px-3 py-3 text-sm md:grid-cols-[minmax(0,1fr)_auto] md:items-center'>
        <div className='min-w-0' style={{ paddingLeft: `${depth * 18}px` }}>
          <div className='flex min-w-0 flex-wrap items-center gap-2'>
            <strong className='truncate'>{item.name}</strong>
            <Badge tone={statusTone(item.status)}>{item.status || '-'}</Badge>
            <Badge tone='neutral'>{item.type || 'department'}</Badge>
          </div>
          <div className='mt-1 truncate text-xs text-muted-foreground'>
            {metadataText(item.metadata?.path) || item.description || item.id}
          </div>
          <div className='mt-2 flex flex-wrap gap-1.5 text-xs'>
            <Badge tone='neutral'>{app.t('members', '成员')}: {formatNumberValue(directMembers)} / {formatNumberValue(totalMembers)}</Badge>
            <Badge tone='neutral'>{app.t('children', '子级')}: {formatNumberValue(childCount)}</Badge>
            <Badge tone='neutral'>{app.t('sort', '排序')}: {formatNumberValue(metadataNumber(item.metadata?.sort))}</Badge>
          </div>
        </div>
        <div className='flex flex-wrap justify-end gap-1.5'>
          {canEdit(item) ? (
            <Button size='sm' variant='outline' onClick={() => onEdit(item)}>
              <Pencil className='size-3.5' />
              {app.t('edit', '编辑')}
            </Button>
          ) : null}
          {canDelete(item) ? (
            <Button size='sm' variant='destructive' onClick={() => onDelete(item)}>
              <Trash2 className='size-3.5' />
              {app.t('delete', '删除')}
            </Button>
          ) : null}
        </div>
      </div>
      {node.children.length ? (
        <div className='border-t border-border/60'>
          {node.children.map((child) => (
            <DepartmentTreeBranch key={child.item.id} node={child} depth={depth + 1} onEdit={onEdit} onDelete={onDelete} canEdit={canEdit} canDelete={canDelete} />
          ))}
        </div>
      ) : null}
    </div>
  )
}

function AssetGroupTreeView({
  groups,
  assets,
  onEdit,
  onDelete,
  canEdit,
  canDelete,
}: {
  groups: PlatformItem[]
  assets: PlatformItem[]
  onEdit: (item: PlatformItem) => void
  onDelete: (item: PlatformItem) => void
  canEdit: (item: PlatformItem) => boolean
  canDelete: (item: PlatformItem) => boolean
}) {
  const app = useApp()
  const tree = useMemo(() => buildAssetGroupTree(groups, assets), [groups, assets])

  if (!groups.length) {
    return (
      <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>
        {app.t('empty', '暂无数据')}
      </div>
    )
  }

  return (
    <div className='overflow-hidden rounded-xl border border-border bg-background/60'>
      <div className='flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2 text-sm'>
        <div className='font-medium'>{app.t('assetGroupTree', '资产组树')}</div>
        <div className='flex flex-wrap gap-2 text-xs text-muted-foreground'>
          <span>{formatNumberValue(groups.length)} {app.t('assetGroups', '资产组')}</span>
          <span>{formatNumberValue(assets.length)} {app.t('assets', '资产')}</span>
        </div>
      </div>
      <div className='divide-y divide-border'>
        {tree.map((node) => (
          <AssetGroupTreeBranch key={node.item.id} node={node} depth={0} onEdit={onEdit} onDelete={onDelete} canEdit={canEdit} canDelete={canDelete} />
        ))}
      </div>
    </div>
  )
}

function AssetGroupTreeBranch({
  node,
  depth,
  onEdit,
  onDelete,
  canEdit,
  canDelete,
}: {
  node: AssetGroupTreeNode
  depth: number
  onEdit: (item: PlatformItem) => void
  onDelete: (item: PlatformItem) => void
  canEdit: (item: PlatformItem) => boolean
  canDelete: (item: PlatformItem) => boolean
}) {
  const app = useApp()
  const item = node.item
  const [expanded, setExpanded] = useState(() => !metadataBool(item.metadata?.collapsed))
  const hasChildren = node.children.length > 0

  useEffect(() => {
    setExpanded(!metadataBool(item.metadata?.collapsed))
  }, [item.id, item.metadata?.collapsed])

  return (
    <div>
      <div className='grid gap-3 px-3 py-3 text-sm md:grid-cols-[minmax(0,1fr)_auto] md:items-center'>
        <div className='min-w-0' style={{ paddingLeft: `${depth * 18}px` }}>
          <div className='flex min-w-0 flex-wrap items-center gap-2'>
            <Button
              size='icon-sm'
              variant='ghost'
              className={cn('size-6', !hasChildren && 'invisible')}
              disabled={!hasChildren}
              aria-label={expanded ? app.t('collapse', '收起') : app.t('expand', '展开')}
              onClick={() => setExpanded((current) => !current)}
            >
              {expanded ? <ChevronDown className='size-3.5' /> : <ChevronRight className='size-3.5' />}
            </Button>
            <strong className='truncate'>{item.name}</strong>
            <Badge tone={statusTone(item.status)}>{item.status || '-'}</Badge>
            <Badge tone='neutral'>{item.protocol || item.type || 'custom'}</Badge>
            {metadataBool(item.metadata?.collapsed) ? <Badge tone='warning'>{app.t('collapsedByDefault', '默认折叠')}</Badge> : null}
          </div>
          <div className='mt-1 truncate text-xs text-muted-foreground'>
            {assetGroupPathText(item) || item.description || item.id}
          </div>
          <div className='mt-2 flex flex-wrap gap-1.5 text-xs'>
            <Badge tone='neutral'>{app.t('directAssets', '直接资产')}: {formatNumberValue(node.directAssetCount)}</Badge>
            <Badge tone='neutral'>{app.t('totalAssets', '累计资产')}: {formatNumberValue(node.totalAssetCount)}</Badge>
            <Badge tone='neutral'>{app.t('children', '子级')}: {formatNumberValue(node.children.length)}</Badge>
            <Badge tone='neutral'>{app.t('sort', '排序')}: {formatNumberValue(metadataNumber(item.metadata?.sort))}</Badge>
          </div>
        </div>
        <div className='flex flex-wrap justify-end gap-1.5'>
          {canEdit(item) ? (
            <Button size='sm' variant='outline' onClick={() => onEdit(item)}>
              <Pencil className='size-3.5' />
              {app.t('edit', '编辑')}
            </Button>
          ) : null}
          {canDelete(item) ? (
            <Button size='sm' variant='destructive' onClick={() => onDelete(item)}>
              <Trash2 className='size-3.5' />
              {app.t('delete', '删除')}
            </Button>
          ) : null}
        </div>
      </div>
      {hasChildren && expanded ? (
        <div className='border-t border-border/60'>
          {node.children.map((child) => (
            <AssetGroupTreeBranch key={child.item.id} node={child} depth={depth + 1} onEdit={onEdit} onDelete={onDelete} canEdit={canEdit} canDelete={canDelete} />
          ))}
        </div>
      ) : null}
    </div>
  )
}

function ResourceHeaderActions({
  config,
  rows,
  onOperation,
  canUsePath,
}: {
  config: PlatformPageConfig
  rows: PlatformItem[]
  onOperation: (operation: ResourceOperation) => void
  canUsePath: CanUsePath
}) {
  const app = useApp()
  const canExport = Boolean(config.apiPath && canUsePath('GET', `${config.apiPath}/export`))
  const canBulkAuthorize = ['assets', 'web_assets', 'database_assets'].includes(config.collection) &&
    canUsePath('POST', `/api/admin/authorizations/${authorizationBulkRoute(config.collection)}/bulk`)

  const exportTable = async (format: 'json' | 'csv') => {
    if (!config.apiPath) return
    try {
      const filename = `openwebservermanager-${config.collection}.${format}`
      await downloadResponse(`${config.apiPath}/export?format=${format}`, filename)
      app.showToast(app.t('tableExported', '表格已导出'))
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const exportButtons = canExport ? (
    <>
      <Button variant='outline' onClick={() => void exportTable('json')}>
        <Download className='size-4' />
        JSON
      </Button>
      <Button variant='outline' onClick={() => void exportTable('csv')}>
        <Download className='size-4' />
        CSV
      </Button>
    </>
  ) : null

  if (config.apiPath?.startsWith('/api/admin/audit/')) {
    return exportButtons
  }

  if (config.collection === 'assets') {
    return (
      <>
        {canBulkAuthorize ? (
          <Button variant='outline' onClick={() => onOperation({ type: 'bulk-authorize', collection: config.collection, items: rows })}>
            <Save className='size-4' />
            批量授权
          </Button>
        ) : null}
        {exportButtons}
        {canUsePath('POST', '/api/admin/assets/import') ? (
          <Button variant='outline' onClick={() => onOperation({ type: 'asset-import' })}>
            <Upload className='size-4' />
            导入
          </Button>
        ) : null}
      </>
    )
  }

  if (config.collection === 'web_assets' || config.collection === 'database_assets') {
    return (
      <>
        {canBulkAuthorize ? (
          <Button variant='outline' onClick={() => onOperation({ type: 'bulk-authorize', collection: config.collection, items: rows })}>
            <Save className='size-4' />
            批量授权
          </Button>
        ) : null}
        {exportButtons}
      </>
    )
  }

  if (config.collection === 'users') {
    return (
      <>
        {exportButtons}
        {canUsePath('POST', '/api/admin/users/import') ? (
          <Button variant='outline' onClick={() => onOperation({ type: 'user-import' })}>
            <Upload className='size-4' />
            导入
          </Button>
        ) : null}
      </>
    )
  }

  if (config.collection === 'certificates') {
    return (
      <>
        {exportButtons}
        {canUsePath('POST', '/api/admin/certificates/acme') ? (
          <Button variant='outline' onClick={() => onOperation({ type: 'certificate-acme' })}>
            <Play className='size-4' />
            ACME
          </Button>
        ) : null}
        {canUsePath('POST', '/api/admin/certificates/dns-providers') ? (
          <Button variant='outline' onClick={() => onOperation({ type: 'certificate-dns-provider' })}>
            <Save className='size-4' />
            DNS provider
          </Button>
        ) : null}
        {canUsePath('POST', '/api/admin/certificates/upload') ? (
          <Button variant='outline' onClick={() => onOperation({ type: 'certificate-upload' })}>
            <Upload className='size-4' />
            上传证书
          </Button>
        ) : null}
        {canUsePath('POST', '/api/admin/certificates/self-signed') ? (
          <Button variant='outline' onClick={() => onOperation({ type: 'certificate-create' })}>
            <Plus className='size-4' />
            自签证书
          </Button>
        ) : null}
      </>
    )
  }

  return exportButtons
}

function ResourceRowActions({
  config,
  item,
  onOperation,
  canUsePath,
}: {
  config: PlatformPageConfig
  item: PlatformItem
  onOperation: (operation: ResourceOperation) => void
  canUsePath: CanUsePath
}) {
  const app = useApp()
  const { confirm, confirmDialog } = useConfirmDialog()
	const [transcoding, setTranscoding] = useState(false)
	const persistedTranscodeStatus = stringValue(item.metadata?.recording_transcode_status)
	const [transcodeStatus, setTranscodeStatus] = useState(persistedTranscodeStatus)

	useEffect(() => {
		setTranscodeStatus(persistedTranscodeStatus)
	}, [persistedTranscodeStatus])

	useEffect(() => {
		if (config.collection !== 'offline_sessions' || !['queued', 'processing'].includes(transcodeStatus)) return
		let alive = true
		const poll = async () => {
			try {
				const status = await apiRequest<RecordingTranscodeStatus>(`/api/admin/audit/offline-sessions/${item.id}/recording/transcode`)
				if (!alive) return
				const nextStatus = status.status || ''
				setTranscodeStatus(nextStatus)
				if (nextStatus === 'completed' || nextStatus === 'failed') {
					await app.refresh(true)
					app.showToast(nextStatus === 'completed' ? app.t('recordingTranscodeCompleted', 'Recording transcode completed') : status.error || app.t('recordingTranscodeFailed', 'Recording transcode failed'))
				}
			} catch (error) {
				if (alive) app.handleApiError(error)
			}
		}
		const timer = window.setInterval(() => void poll(), 1000)
		return () => {
			alive = false
			window.clearInterval(timer)
		}
	}, [config.collection, item.id, transcodeStatus])

  const runTask = async () => {
    try {
      await apiRequest(`/api/admin/scheduled-tasks/${item.id}/run`, { method: 'POST', body: '{}' })
      await app.refresh(true)
      app.showToast('任务已触发')
    } catch (error) {
      await app.refresh(true)
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

  const downloadCertificateBundle = async () => {
    try {
      await downloadResponse(`/api/admin/certificates/${item.id}/bundle`, `${item.name || item.id}.zip`)
      app.showToast(app.t('certificateBundleDownloaded', 'Certificate bundle downloaded'))
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const setDefaultCertificate = async () => {
    try {
      await apiRequest(`/api/admin/certificates/${item.id}/default`, { method: 'POST', body: '{}' })
      await app.refresh(true)
      app.showToast(app.t('defaultCertificateUpdated', 'Default certificate updated'))
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const disconnectSession = async () => {
    const confirmed = await confirm({
      title: `断开 ${item.name || item.id}?`,
      description: '该在线会话会被强制断开，用户需要重新接入资产。',
      confirmText: '断开',
      destructive: true,
    })
    if (!confirmed) return
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
    const confirmed = await confirm({
      title: `删除 ${item.name || item.id} 的录屏?`,
      description: '录屏文件删除后不可恢复。',
      confirmText: '删除录屏',
      destructive: true,
    })
    if (!confirmed) return
    try {
      await apiRequest(`/api/admin/audit/offline-sessions/${item.id}/recording`, { method: 'DELETE' })
      await app.refresh(true)
      app.showToast('录屏已删除')
    } catch (error) {
      app.handleApiError(error)
    }
  }

	const transcodeRecording = async () => {
		setTranscoding(true)
		try {
			const status = await apiRequest<RecordingTranscodeStatus>(`/api/admin/audit/offline-sessions/${item.id}/recording/transcode`, { method: 'POST', body: '{}' })
			setTranscodeStatus(status.status || 'queued')
			await app.refresh(true)
			app.showToast(app.t('recordingTranscodeQueued', 'Recording transcode queued'))
		} catch (error) {
			app.handleApiError(error)
		} finally {
			setTranscoding(false)
		}
	}

  if (config.collection === 'online_sessions') {
    if (!canUsePath('POST', `/api/admin/audit/online-sessions/${item.id}/disconnect`)) return null
    return (
      <>
        <Button size='sm' variant='destructive' onClick={() => void disconnectSession()}>
          <Trash2 className='size-3.5' />
          断开
        </Button>
        {confirmDialog}
      </>
    )
  }

  if (config.collection === 'offline_sessions' && itemHasRecording(item)) {
    const recordingPath = `/api/admin/audit/offline-sessions/${item.id}/recording`
    const playbackPath = `${recordingPath}/playback`
    const canPlaybackRecording = canUsePath('GET', playbackPath)
    const canDownloadRecording = canUsePath('GET', recordingPath)
    const canDeleteRecording = canUsePath('DELETE', recordingPath)
		const transcodePath = `${recordingPath}/transcode`
		const canTranscodeRecording = canUsePath('POST', transcodePath)
		const transcodeRunning = transcoding || transcodeStatus === 'queued' || transcodeStatus === 'processing'
		if (!canPlaybackRecording && !canDownloadRecording && !canDeleteRecording && !canTranscodeRecording) return null
    return (
      <>
				{transcodeStatus ? (
					<Badge tone={transcodeStatus === 'completed' ? 'success' : transcodeStatus === 'failed' ? 'danger' : 'neutral'}>
						{app.t(`recordingTranscodeStatus.${transcodeStatus}`, transcodeStatus)}
					</Badge>
				) : null}
        {canPlaybackRecording ? (
          <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'recording-playback', item })}>
            <Play className='size-3.5' />
            {app.t('recordingPlayback', 'Playback')}
          </Button>
        ) : null}
				{canTranscodeRecording ? (
					<Button size='sm' variant='outline' onClick={() => void transcodeRecording()} disabled={transcodeRunning}>
						{transcodeRunning ? <Loader2 className='size-3.5 animate-spin' /> : <Film className='size-3.5' />}
						{app.t(transcodeStatus === 'completed' || transcodeStatus === 'failed' ? 'retryRecordingTranscode' : 'transcodeRecording', transcodeStatus ? 'Retry transcode' : 'Transcode')}
					</Button>
				) : null}
        {canDownloadRecording ? (
          <Button size='sm' variant='outline' onClick={() => void downloadRecording()}>
            <Download className='size-3.5' />
            下载录屏
          </Button>
        ) : null}
        {canDeleteRecording ? (
          <Button size='sm' variant='destructive' onClick={() => void deleteRecording()}>
            <Trash2 className='size-3.5' />
            删除录屏
          </Button>
        ) : null}
        {canDeleteRecording ? confirmDialog : null}
      </>
    )
  }

  if (config.collection === 'storages') {
    if (!canUsePath('GET', `/api/admin/storages/${item.id}/files`)) return null
    return (
      <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'storage-files', item })}>
        <FileSearch className='size-3.5' />
        文件
      </Button>
    )
  }

  if (config.collection === 'certificates') {
    const certificatePath = `/api/admin/certificates/${item.id}`
    const canDownload = canUsePath('GET', `${certificatePath}/download`)
    const canDownloadBundle = canUsePath('GET', `${certificatePath}/bundle`)
    const canSetDefault = canUsePath('POST', `${certificatePath}/default`)
    const canEditMTLS = canUsePath('POST', `${certificatePath}/mtls`)
    const canViewLogs = canUsePath('GET', `${certificatePath}/logs`)
    if (!canDownload && !canDownloadBundle && !canSetDefault && !canEditMTLS && !canViewLogs) return null
    return (
      <>
        {canDownload ? (
          <Button size='sm' variant='outline' onClick={() => void downloadCertificate()}>
            <FileDown className='size-3.5' />
            下载
          </Button>
        ) : null}
        {canDownloadBundle ? (
          <Button size='sm' variant='outline' onClick={() => void downloadCertificateBundle()}>
            <Download className='size-3.5' />
            {app.t('bundle', 'Bundle')}
          </Button>
        ) : null}
        {canSetDefault ? (
          <Button size='sm' variant='outline' onClick={() => void setDefaultCertificate()}>
            <Save className='size-3.5' />
            默认
          </Button>
        ) : null}
        {canEditMTLS ? (
          <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'certificate-mtls', item })}>
            <ShieldCheck className='size-3.5' />
            mTLS
          </Button>
        ) : null}
        {canViewLogs ? (
          <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'certificate-logs', item })}>
            <FileSearch className='size-3.5' />
            日志
          </Button>
        ) : null}
      </>
    )
  }

  if (config.collection === 'agent_gateways') {
    const canReadStatus = canUsePath('GET', '/api/admin/agent-gateways/status')
    const canIssueToken = canUsePath('POST', `/api/admin/agent-gateways/${item.id}/token`)
    if (!canReadStatus && !canIssueToken) return null
    return (
      <>
        {canReadStatus ? (
          <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'gateway-status', collection: 'agent_gateways', item })}>
            <FileSearch className='size-3.5' />
            {app.t('gatewayStatus', 'Status')}
          </Button>
        ) : null}
        {canIssueToken ? (
          <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'agent-token', item })}>
            <Copy className='size-3.5' />
            令牌
          </Button>
        ) : null}
      </>
    )
  }

  if (config.collection === 'gateway_groups') {
    if (!canUsePath('GET', '/api/admin/gateway-groups/status')) return null
    return (
      <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'gateway-status', collection: 'gateway_groups', item })}>
        <FileSearch className='size-3.5' />
        {app.t('gatewayStatus', 'Status')}
      </Button>
    )
  }

  if (config.collection === 'scheduled_tasks') {
    const taskPath = `/api/admin/scheduled-tasks/${item.id}`
    const canRunTask = canUsePath('POST', `${taskPath}/run`)
    const canViewTaskLogs = canUsePath('GET', `${taskPath}/logs`)
    if (!canRunTask && !canViewTaskLogs) return null
    return (
      <>
        {canRunTask ? (
          <Button size='sm' variant='outline' onClick={() => void runTask()}>
            <Play className='size-3.5' />
            运行
          </Button>
        ) : null}
        {canViewTaskLogs ? (
          <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'task-logs', item })}>
            <FileSearch className='size-3.5' />
            日志
          </Button>
        ) : null}
      </>
    )
  }

  if (config.collection === 'sql_work_orders') {
    const status = (item.status || '').toLowerCase()
    const orderPath = `/api/admin/sql-work-orders/${item.id}`
    if (status === 'pending' || status === 'submitted' || status === 'requested') {
      const canApprove = canUsePath('POST', `${orderPath}/approve`)
      const canReject = canUsePath('POST', `${orderPath}/reject`)
      if (!canApprove && !canReject) return null
      return (
        <>
          {canApprove ? (
            <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'sql-decision', item, decision: 'approve' })}>
              <Save className='size-3.5' />
              批准
            </Button>
          ) : null}
          {canReject ? (
            <Button size='sm' variant='destructive' onClick={() => onOperation({ type: 'sql-decision', item, decision: 'reject' })}>
              <Trash2 className='size-3.5' />
              拒绝
            </Button>
          ) : null}
        </>
      )
    }
    if (status !== 'approved') return null
    if (!canUsePath('POST', `${orderPath}/execute`)) return null
    return (
      <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'sql-execute', item })}>
        <Play className='size-3.5' />
        执行
      </Button>
    )
  }

  if (config.collection === 'command_approvals') {
    const status = (item.status || '').toLowerCase()
    const approvalPath = `/api/admin/command-approvals/${item.id}`
    if (status === 'pending' || status === 'submitted' || status === 'requested') {
      const canApprove = canUsePath('POST', `${approvalPath}/approve`)
      const canReject = canUsePath('POST', `${approvalPath}/reject`)
      if (!canApprove && !canReject) return null
      return (
        <>
          {canApprove ? (
            <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'command-decision', item, decision: 'approve' })}>
              <Save className='size-3.5' />
              批准
            </Button>
          ) : null}
          {canReject ? (
            <Button size='sm' variant='destructive' onClick={() => onOperation({ type: 'command-decision', item, decision: 'reject' })}>
              <Trash2 className='size-3.5' />
              拒绝
            </Button>
          ) : null}
        </>
      )
    }
    if (status !== 'approved') return null
    if (!canUsePath('POST', `${approvalPath}/execute`)) return null
    return (
      <Button size='sm' variant='outline' onClick={() => onOperation({ type: 'command-execute', item })}>
        <Play className='size-3.5' />
        执行
      </Button>
    )
  }

  return null
}

function ResourceOperationDialog({
  operation,
  onOpenChange,
  requestAccessMFACode,
  canUsePath,
}: {
  operation: ResourceOperation | null
  onOpenChange: (operation: ResourceOperation | null) => void
  requestAccessMFACode: RequestAccessMFACode
  canUsePath: CanUsePath
}) {
  if (!operation) return null
  if (operation.type === 'asset-import') return <AssetImportDialog onClose={() => onOpenChange(null)} canSubmit={canUsePath('POST', '/api/admin/assets/import')} />
  if (operation.type === 'user-import') return <UserImportDialog onClose={() => onOpenChange(null)} canSubmit={canUsePath('POST', '/api/admin/users/import')} />
  if (operation.type === 'bulk-authorize') return <BulkAuthorizeDialog collection={operation.collection} items={operation.items} onClose={() => onOpenChange(null)} canSubmit={canUsePath('POST', `/api/admin/authorizations/${authorizationBulkRoute(operation.collection)}/bulk`)} />
  if (operation.type === 'agent-token') return <AgentGatewayTokenDialog item={operation.item} onClose={() => onOpenChange(null)} canIssueToken={canUsePath('POST', `/api/admin/agent-gateways/${operation.item.id}/token`)} />
  if (operation.type === 'gateway-status') {
    const path = operation.collection === 'agent_gateways' ? '/api/admin/agent-gateways/status' : '/api/admin/gateway-groups/status'
    return <GatewayStatusDialog collection={operation.collection} item={operation.item} onClose={() => onOpenChange(null)} canRead={canUsePath('GET', path)} />
  }
  if (operation.type === 'certificate-create') return <CertificateCreateDialog onClose={() => onOpenChange(null)} canSubmit={canUsePath('POST', '/api/admin/certificates/self-signed')} />
  if (operation.type === 'certificate-upload') return <CertificateUploadDialog onClose={() => onOpenChange(null)} canUpload={canUsePath('POST', '/api/admin/certificates/upload')} />
  if (operation.type === 'certificate-acme') return <CertificateACMEDialog onClose={() => onOpenChange(null)} canUsePath={canUsePath} />
  if (operation.type === 'certificate-dns-provider') return <CertificateDNSProviderDialog onClose={() => onOpenChange(null)} canUsePath={canUsePath} />
  if (operation.type === 'certificate-logs') return <CertificateLogsDialog item={operation.item} onClose={() => onOpenChange(null)} canRead={canUsePath('GET', `/api/admin/certificates/${operation.item.id}/logs`)} />
  if (operation.type === 'certificate-mtls') return <CertificateMTLSDialog item={operation.item} onClose={() => onOpenChange(null)} canSave={canUsePath('POST', `/api/admin/certificates/${operation.item.id}/mtls`)} />
  if (operation.type === 'recording-playback') return <RecordingPlaybackDialog item={operation.item} onClose={() => onOpenChange(null)} canRead={canUsePath('GET', `/api/admin/audit/offline-sessions/${operation.item.id}/recording/playback`)} />
  if (operation.type === 'storage-files') return <StorageFilesDialog item={operation.item} onClose={() => onOpenChange(null)} canUsePath={canUsePath} />
  if (operation.type === 'task-logs') return <TaskLogsDialog item={operation.item} onClose={() => onOpenChange(null)} canRead={canUsePath('GET', `/api/admin/scheduled-tasks/${operation.item.id}/logs`)} />
  if (operation.type === 'sql-decision') return <SQLWorkOrderDecisionDialog item={operation.item} decision={operation.decision} onClose={() => onOpenChange(null)} canSubmit={canUsePath('POST', `/api/admin/sql-work-orders/${operation.item.id}/${operation.decision}`)} />
  if (operation.type === 'sql-execute') return <SQLExecuteDialog item={operation.item} onClose={() => onOpenChange(null)} requestAccessMFACode={requestAccessMFACode} canExecute={canUsePath('POST', `/api/admin/sql-work-orders/${operation.item.id}/execute`)} />
  if (operation.type === 'command-decision') return <CommandApprovalDecisionDialog item={operation.item} decision={operation.decision} onClose={() => onOpenChange(null)} canSubmit={canUsePath('POST', `/api/admin/command-approvals/${operation.item.id}/${operation.decision}`)} />
  if (operation.type === 'command-execute') return <CommandApprovalExecuteDialog item={operation.item} onClose={() => onOpenChange(null)} requestAccessMFACode={requestAccessMFACode} canExecute={canUsePath('POST', `/api/admin/command-approvals/${operation.item.id}/execute`)} />
  return null
}

function RecordingPlaybackDialog({ item, onClose, canRead }: { item: PlatformItem; onClose: () => void; canRead: boolean }) {
  const app = useApp()
	const transcodeQuery = useQuery({
		queryKey: ['recording-transcode', item.id],
		queryFn: () => apiRequest<RecordingTranscodeStatus>(`/api/admin/audit/offline-sessions/${item.id}/recording/transcode`),
		enabled: canRead,
		refetchInterval: (query) => ['queued', 'processing'].includes(query.state.data?.status || '') ? 1000 : false,
	})
	const videoURL = transcodeQuery.data?.video_url || ''
  const [container, setContainer] = useState<HTMLDivElement | null>(null)
  const recordingRef = useRef<any>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [duration, setDuration] = useState(0)
  const [position, setPosition] = useState(0)
  const [playing, setPlaying] = useState(false)

  useEffect(() => {
    const Guacamole = window.Guacamole
		if (transcodeQuery.isPending) return
		if (videoURL) {
			setLoading(false)
			setError('')
			return
		}
		if (!container) return
    if (!canRead) {
      setLoading(false)
      setError(app.t('permissionDenied', 'Permission denied'))
      return
    }
    if (!Guacamole?.SessionRecording) {
      setLoading(false)
      setError(app.t('workspace.missingGuacamole', 'Guacamole playback library is unavailable.'))
      return
    }
    let resizeObserver: ResizeObserver | null = null
    let alive = true
    try {
      const tunnel = new Guacamole.StaticHTTPTunnel(`/api/admin/audit/offline-sessions/${item.id}/recording/playback`, true)
      const recording = new Guacamole.SessionRecording(tunnel)
      recordingRef.current = recording
      const display = recording.getDisplay()
      const element = display.getElement()
      element.style.margin = 'auto'
      container.replaceChildren(element)
      const scaleDisplay = () => {
        const width = Math.max(1, Number(display.getWidth?.()) || element.clientWidth || 1)
        const height = Math.max(1, Number(display.getHeight?.()) || element.clientHeight || 1)
        display.scale(Math.min(container.clientWidth / width, container.clientHeight / height, 1))
      }
      resizeObserver = new ResizeObserver(scaleDisplay)
      resizeObserver.observe(container)
      recording.onprogress = (nextDuration: number) => {
        if (alive) setDuration(Math.max(0, nextDuration || recording.getDuration()))
      }
      recording.onseek = (nextPosition: number) => {
        if (alive) setPosition(Math.max(0, nextPosition || 0))
      }
      recording.onplay = () => alive && setPlaying(true)
      recording.onpause = () => {
        if (!alive) return
        setPosition(Math.max(0, recording.getPosition()))
        setPlaying(false)
      }
      recording.onerror = (message: string) => {
        if (!alive) return
        setLoading(false)
        setError(message || app.t('recordingPlaybackFailed', 'Unable to load recording.'))
      }
      recording.onload = () => {
        if (!alive) return
        const nextDuration = Math.max(0, recording.getDuration())
        setDuration(nextDuration)
        setLoading(false)
        recording.seek(0, scaleDisplay)
      }
      recording.connect()
    } catch (loadError) {
      setLoading(false)
      setError(loadError instanceof Error ? loadError.message : app.t('recordingPlaybackFailed', 'Unable to load recording.'))
    }
    return () => {
      alive = false
      resizeObserver?.disconnect()
      recordingRef.current?.abort?.()
      recordingRef.current = null
      container.replaceChildren()
    }
	}, [canRead, container, item.id, transcodeQuery.isPending, videoURL])

  useEffect(() => {
    if (!playing) return
    const timer = window.setInterval(() => {
      const recording = recordingRef.current
      if (recording) setPosition(Math.max(0, recording.getPosition()))
    }, 100)
    return () => window.clearInterval(timer)
  }, [playing])

  const togglePlayback = () => {
    const recording = recordingRef.current
    if (!recording || loading || error) return
    if (recording.isPlaying()) recording.pause()
    else recording.play()
  }

  const seek = (nextPosition: number) => {
    const recording = recordingRef.current
    if (!recording || loading || error) return
    recording.seek(nextPosition, () => setPosition(nextPosition))
  }

  const restart = () => {
    const recording = recordingRef.current
    if (!recording || loading || error) return
    recording.seek(0, () => {
      setPosition(0)
      recording.play()
    })
  }

  return (
		<DialogShell open onOpenChange={(open) => !open && onClose()} title={app.t('recordingPlayback', 'Recording playback')} description={videoURL ? app.t('recordingVideoPlaybackDescription', 'Play the transcoded session video in the browser.') : app.t('recordingPlaybackDescription', 'Replay the raw Guacamole session recording in the browser.')}>
      <div className='grid gap-4'>
        <div className='relative grid min-h-[360px] place-items-center overflow-hidden rounded-lg border border-border bg-black'>
					{videoURL ? (
						<video className='h-[min(62vh,640px)] min-h-[360px] w-full bg-black object-contain' src={videoURL} controls autoPlay={false} preload='metadata' />
					) : (
						<div ref={setContainer} className='flex h-[min(62vh,640px)] min-h-[360px] w-full items-center justify-center overflow-hidden' />
					)}
          {loading ? <div className='absolute inset-0 grid place-items-center bg-black/70 text-sm text-white'>{app.t('recordingLoading', 'Loading recording...')}</div> : null}
          {error ? <div className='absolute inset-0 grid place-items-center bg-black/80 p-6 text-center text-sm text-red-200'>{error}</div> : null}
        </div>
				{videoURL ? null : <div className='grid gap-3 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:items-center'>
          <div className='flex gap-2'>
            <Button size='icon-sm' variant='outline' onClick={togglePlayback} disabled={loading || Boolean(error) || duration <= 0} title={playing ? app.t('pauseRecording', 'Pause') : app.t('playRecording', 'Play')}>
              {playing ? <Pause className='size-4' /> : <Play className='size-4' />}
            </Button>
            <Button size='icon-sm' variant='outline' onClick={restart} disabled={loading || Boolean(error) || duration <= 0} title={app.t('restartRecording', 'Restart')}>
              <RotateCcw className='size-4' />
            </Button>
          </div>
          <input
            type='range'
            min={0}
            max={Math.max(duration, 1)}
            step={100}
            value={Math.min(position, Math.max(duration, 1))}
            onChange={(event) => seek(Number(event.currentTarget.value))}
            disabled={loading || Boolean(error) || duration <= 0}
            aria-label={app.t('recordingPlaybackPosition', 'Playback position')}
            className='h-2 w-full accent-primary'
          />
          <div className='text-right font-mono text-xs text-muted-foreground'>{formatPlaybackTime(position)} / {formatPlaybackTime(duration)}</div>
				</div>}
				{transcodeQuery.data?.status === 'failed' ? <div className='text-sm text-destructive'>{transcodeQuery.data.error || app.t('recordingTranscodeFailed', 'Recording transcode failed')}</div> : null}
      </div>
    </DialogShell>
  )
}

function formatPlaybackTime(milliseconds: number) {
  const totalSeconds = Math.max(0, Math.floor(milliseconds / 1000))
  const hours = Math.floor(totalSeconds / 3600)
  const minutes = Math.floor((totalSeconds % 3600) / 60)
  const seconds = totalSeconds % 60
  return hours > 0
    ? `${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
    : `${minutes}:${String(seconds).padStart(2, '0')}`
}

function AssetImportDialog({ onClose, canSubmit }: { onClose: () => void; canSubmit: boolean }) {
  const app = useApp()
  const [format, setFormat] = useState<'json' | 'csv'>('json')
  const [content, setContent] = useState(assetImportJSONSample)
  const [updateExisting, setUpdateExisting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [summary, setSummary] = useState<ImportSummary | null>(null)

  const changeFormat = (next: 'json' | 'csv') => {
    setFormat(next)
    setContent(next === 'csv' ? assetImportCSVSample : assetImportJSONSample)
    setSummary(null)
  }

  const submit = async () => {
    if (!canSubmit) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setSaving(true)
    setSummary(null)
    try {
      const payload = format === 'csv'
        ? { format: 'csv', content, update_existing: updateExisting }
        : (() => {
          const parsed = JSON.parse(content) as unknown
          return Array.isArray(parsed)
            ? { update_existing: updateExisting, items: parsed }
            : typeof parsed === 'object' && parsed !== null
              ? { ...(parsed as Record<string, unknown>), update_existing: updateExisting }
              : parsed
        })()
      const data = await apiRequest<{ items?: PlatformItem[]; summary?: ImportSummary }>('/api/admin/assets/import', { method: 'POST', body: JSON.stringify(payload) })
      setSummary(data.summary || { created: data.items?.length || 0, total: data.items?.length || 0 })
      await app.refresh(true)
      app.showToast('资产已导入')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title='导入资产' description='粘贴 JSON 或 CSV，支持按资产名称跳过或更新已有资产。'>
      <div className='grid gap-4'>
        <div className='grid gap-3 sm:grid-cols-2'>
          <Field label='格式'>
            <Select value={format} onChange={(event) => changeFormat(event.currentTarget.value as 'json' | 'csv')}>
              <option value='json'>JSON</option>
              <option value='csv'>CSV</option>
            </Select>
          </Field>
        </div>
        <Field label={format === 'csv' ? '资产 CSV' : '资产 JSON'}>
          <Textarea className='min-h-64 font-mono text-xs' value={content} onChange={(event) => { setContent(event.currentTarget.value); setSummary(null) }} />
        </Field>
        {format === 'csv' ? (
          <div className='rounded-lg border border-border bg-muted/30 p-3 text-xs leading-5 text-muted-foreground'>
            第一行必须是表头。常用列：name,type,status,protocol,host,port,group,tags,credential_id,gateway_group_id,metadata_json。
          </div>
        ) : null}
        <CheckboxRow
          checked={updateExisting}
          onChange={(checked) => { setUpdateExisting(checked); setSummary(null) }}
          label='更新已有同名资产；关闭时自动跳过已有资产'
        />
        {summary ? <ImportSummaryPanel summary={summary} /> : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>{summary ? '关闭' : '取消'}</Button>
          <Button variant='primary' onClick={() => void submit()} disabled={saving || !canSubmit}>
            <Upload className='size-4' />
            {saving ? '导入中' : summary ? '重新导入' : '导入'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function UserImportDialog({ onClose, canSubmit }: { onClose: () => void; canSubmit: boolean }) {
  const app = useApp()
  const [format, setFormat] = useState<'json' | 'csv'>('json')
  const [content, setContent] = useState(userImportJSONSample)
  const [updateExisting, setUpdateExisting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [summary, setSummary] = useState<ImportSummary | null>(null)

  const changeFormat = (next: 'json' | 'csv') => {
    setFormat(next)
    setContent(next === 'csv' ? userImportCSVSample : userImportJSONSample)
    setSummary(null)
  }

  const submit = async () => {
    if (!canSubmit) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setSaving(true)
    setSummary(null)
    try {
      const payload = format === 'csv'
        ? { format: 'csv', content, update_existing: updateExisting }
        : (() => {
          const parsed = JSON.parse(content) as unknown
          return Array.isArray(parsed)
            ? { update_existing: updateExisting, items: parsed }
            : typeof parsed === 'object' && parsed !== null
              ? { ...(parsed as Record<string, unknown>), update_existing: updateExisting }
              : parsed
        })()
      const data = await apiRequest<{ summary?: ImportSummary }>('/api/admin/users/import', { method: 'POST', body: JSON.stringify(payload) })
      setSummary(data.summary || null)
      await app.refresh(true)
      app.showToast('用户已导入')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title='导入用户' description='粘贴 JSON 或 CSV，支持按用户名跳过或更新已有用户。'>
      <div className='grid gap-4'>
        <div className='grid gap-3 sm:grid-cols-2'>
          <Field label='格式'>
            <Select value={format} onChange={(event) => changeFormat(event.currentTarget.value as 'json' | 'csv')}>
              <option value='json'>JSON</option>
              <option value='csv'>CSV</option>
            </Select>
          </Field>
        </div>
        <Field label={format === 'csv' ? '用户 CSV' : '用户 JSON'}>
          <Textarea className='min-h-64 font-mono text-xs' value={content} onChange={(event) => { setContent(event.currentTarget.value); setSummary(null) }} />
        </Field>
        <div className='rounded-lg border border-border bg-muted/30 p-3 text-xs leading-5 text-muted-foreground'>
          本地用户必须提供至少 8 位密码；角色可写入 CSV 的 role 列或 JSON 的 metadata.role，支持 user、auditor、admin 或自定义角色名。
        </div>
        <CheckboxRow
          checked={updateExisting}
          onChange={(checked) => { setUpdateExisting(checked); setSummary(null) }}
          label='更新已有同名用户；关闭时自动跳过已有用户'
        />
        {summary ? <ImportSummaryPanel summary={summary} /> : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>{summary ? '关闭' : '取消'}</Button>
          <Button variant='primary' onClick={() => void submit()} disabled={saving || !canSubmit}>
            <Upload className='size-4' />
            {saving ? '导入中' : summary ? '重新导入' : '导入'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function ImportSummaryPanel({ summary }: { summary: ImportSummary }) {
  const labels: Record<string, string> = {
    created: '创建',
    updated: '更新',
    skipped: '跳过',
    failed: '失败',
    total: '总计',
  }
  const orderedKeys = ['created', 'updated', 'skipped', 'failed', 'total']
  const keys = [
    ...orderedKeys.filter((key) => typeof summary[key] === 'number'),
    ...Object.keys(summary).filter((key) => !orderedKeys.includes(key) && typeof summary[key] === 'number'),
  ]

  if (!keys.length) return null

  return (
    <div className='grid gap-2 rounded-lg border border-border bg-muted/30 p-3 text-xs text-muted-foreground'>
      <div className='font-medium text-foreground'>导入结果</div>
      <div className='grid gap-2 sm:grid-cols-4'>
        {keys.map((key) => (
          <div key={key} className='rounded-md border border-border/70 bg-background/70 px-2.5 py-2'>
            <span>{labels[key] || key}</span>
            <strong className='ml-2 font-mono text-foreground'>{summary[key]}</strong>
          </div>
        ))}
      </div>
    </div>
  )
}

function BulkAuthorizeDialog({ collection, items, onClose, canSubmit }: { collection: string; items: PlatformItem[]; onClose: () => void; canSubmit: boolean }) {
  const app = useApp()
  const [subjectIDs, setSubjectIDs] = useState('')
  const [targetIDs, setTargetIDs] = useState(items.map((item) => item.id).join('\n'))
  const [selectedGroupID, setSelectedGroupID] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [saving, setSaving] = useState(false)
  const [summary, setSummary] = useState<Record<string, number> | null>(null)
  const route = authorizationBulkRoute(collection)
  const groupOptions = useMemo(() => authorizationGroupOptions(collection, app.data.platform?.asset_groups || []), [app.data.platform?.asset_groups, collection])
  const targetHelp = authorizationTargetHelp(collection)

  const submit = async () => {
    if (!canSubmit) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setSaving(true)
    try {
      const data = await apiRequest<{ summary?: Record<string, number> }>(`/api/admin/authorizations/${route}/bulk`, {
        method: 'POST',
        body: JSON.stringify({
          subject_ids: splitLines(subjectIDs),
          target_ids: splitLines(targetIDs),
          expires_at: expiresAt || undefined,
          type: 'bulk',
          status: 'enabled',
        }),
      })
      setSummary(data.summary || null)
      await app.refresh(true)
      app.showToast('批量授权已完成')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  const appendGroupTarget = () => {
    if (!selectedGroupID) return
    setTargetIDs((current) => appendUniqueLine(current, selectedGroupID))
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title='批量授权' description='按用户、部门、资产或资产组 ID 批量生成授权记录；重复的主体/目标组合会自动跳过。'>
      <div className='grid gap-4'>
        <Field label='主体 ID'>
          <Textarea className='min-h-32 font-mono text-xs' value={subjectIDs} onChange={(event) => setSubjectIDs(event.currentTarget.value)} placeholder='每行一个用户 ID、用户名、部门 ID 或部门名称' />
        </Field>
        {groupOptions.length ? (
          <div className='grid gap-2 rounded-lg border border-border bg-muted/20 p-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end'>
            <Field label='追加资产组'>
              <Select value={selectedGroupID} onChange={(event) => setSelectedGroupID(event.currentTarget.value)}>
                <option value=''>选择一个资产组</option>
                {groupOptions.map((group) => (
                  <option key={group.id} value={group.id}>{group.name} · {group.protocol || group.type || 'custom'}</option>
                ))}
              </Select>
            </Field>
            <Button variant='outline' onClick={appendGroupTarget} disabled={!selectedGroupID}>
              <FolderPlus className='size-4' />
              追加
            </Button>
          </div>
        ) : null}
        <Field label='目标资源 ID'>
          <Textarea className='min-h-40 font-mono text-xs' value={targetIDs} onChange={(event) => setTargetIDs(event.currentTarget.value)} placeholder={targetHelp} />
        </Field>
        <Field label='失效时间'>
          <Input value={expiresAt} onChange={(event) => setExpiresAt(event.currentTarget.value)} placeholder='2026-12-31T23:59:59Z，可留空' />
        </Field>
        {summary ? (
          <div className='rounded-lg border border-border bg-muted/30 p-3 text-xs text-muted-foreground'>
            创建 {summary.created || 0}，更新 {summary.updated || 0}，跳过 {summary.skipped || 0}，总计 {summary.total || 0}
          </div>
        ) : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>关闭</Button>
          <Button variant='primary' onClick={() => void submit()} disabled={saving || !canSubmit || !splitLines(subjectIDs).length || !splitLines(targetIDs).length}>
            <Save className='size-4' />
            {saving ? '授权中' : '生成授权'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function authorizationBulkRoute(collection: string) {
  if (collection === 'web_assets') return 'websites'
  if (collection === 'database_assets') return 'databases'
  return 'assets'
}

function authorizationTargetHelp(collection: string) {
  if (collection === 'web_assets') return '每行一个 Web 资产 ID、Web 资产名称、资产组 ID 或资产组名称'
  if (collection === 'database_assets') return '每行一个数据库资产 ID、数据库资产名称、资产组 ID 或资产组名称'
  return '每行一个资产 ID、资产名称、资产组 ID 或资产组名称'
}

function authorizationGroupOptions(collection: string, groups: PlatformItem[]) {
  const score = (group: PlatformItem) => {
    const kind = `${group.type || ''} ${group.protocol || ''}`.toLowerCase()
    if (collection === 'web_assets') return kind.includes('web') || kind.includes('http') ? 0 : 1
    if (collection === 'database_assets') return kind.includes('database') || kind.includes('db') || kind.includes('sql') ? 0 : 1
    return kind.includes('ssh') || kind.includes('rdp') || kind.includes('vnc') || kind.includes('desktop') || kind.includes('text') ? 0 : 1
  }
  return [...groups].sort((left, right) => score(left) - score(right) || assetGroupTreeSort(left, right))
}

function appendUniqueLine(current: string, value: string) {
  const lines = splitLines(current)
  const key = value.trim().toLowerCase()
  if (!key || lines.some((line) => line.toLowerCase() === key)) return current
  return [...lines, value.trim()].join('\n')
}

function quotePOSIXShell(value: string) {
  return `'${value.replaceAll("'", "'\"'\"'")}'`
}

function quotePowerShell(value: string) {
  return `'${value.replaceAll("'", "''")}'`
}

function GatewayStatusDialog({
  collection,
  item,
  onClose,
  canRead,
}: {
  collection: 'agent_gateways' | 'gateway_groups'
  item: PlatformItem
  onClose: () => void
  canRead: boolean
}) {
  const app = useApp()
  const isAgent = collection === 'agent_gateways'
  const endpoint = isAgent ? '/api/admin/agent-gateways/status' : '/api/admin/gateway-groups/status'
  const statusQuery = useQuery<AgentGatewayStatusResponse | GatewayGroupStatusResponse>({
    queryKey: ['gateway-runtime-status', collection],
    queryFn: () => isAgent
      ? apiRequest<AgentGatewayStatusResponse>(endpoint)
      : apiRequest<GatewayGroupStatusResponse>(endpoint),
    enabled: canRead,
    refetchInterval: 5_000,
  })
  const agentPayload = isAgent ? statusQuery.data as AgentGatewayStatusResponse | undefined : undefined
  const groupPayload = !isAgent ? statusQuery.data as GatewayGroupStatusResponse | undefined : undefined
  const agent = agentPayload?.items?.find((candidate) => candidate.id === item.id)
  const group = groupPayload?.items?.find((candidate) => candidate.id === item.id)
  const checkedAt = agentPayload?.checked_at || groupPayload?.checked_at || group?.checked_at

  return (
    <DialogShell
      open
      onOpenChange={(open) => { if (!open) onClose() }}
      title={`${item.name || item.id} · ${app.t('gatewayStatus', 'Gateway status')}`}
      description={app.t('gatewayStatusDescription', 'Live heartbeat, resource, routing, and member status. Data refreshes every five seconds.')}
    >
      <div className='grid gap-4'>
        <div className='flex flex-wrap items-center justify-between gap-3'>
          <div className='flex flex-wrap items-center gap-2'>
            <Badge tone={statusTone(agent?.status || group?.status || item.status)}>{agent?.status || group?.status || item.status || '-'}</Badge>
            {checkedAt ? <span className='text-xs text-muted-foreground'>{app.t('checkedAt', 'Checked')}: {formatDate(checkedAt)}</span> : null}
          </div>
          <Button size='sm' variant='outline' onClick={() => void statusQuery.refetch()} disabled={!canRead || statusQuery.isFetching}>
            <RefreshCw className={statusQuery.isFetching ? 'size-3.5 animate-spin' : 'size-3.5'} />
            {app.t('refresh', 'Refresh')}
          </Button>
        </div>

        {!canRead ? <p className='text-sm text-destructive'>{app.t('permissionDenied', 'Permission denied')}</p> : null}
        {statusQuery.isLoading ? <p className='text-sm text-muted-foreground'>{app.t('loading', 'Loading...')}</p> : null}
        {statusQuery.error ? <p className='text-sm text-destructive'>{statusQuery.error instanceof Error ? statusQuery.error.message : String(statusQuery.error)}</p> : null}

        {agent ? <AgentGatewayStatusContent item={agent} summary={agentPayload} /> : null}
        {group ? <GatewayGroupStatusContent status={group} /> : null}
        {canRead && !statusQuery.isLoading && !statusQuery.error && !agent && !group ? (
          <p className='text-sm text-muted-foreground'>{app.t('gatewayStatusMissing', 'Gateway status is not available.')}</p>
        ) : null}
      </div>
    </DialogShell>
  )
}

function AgentGatewayStatusContent({ item, summary }: { item: PlatformItem; summary?: AgentGatewayStatusResponse }) {
  const app = useApp()
  const metadata = item.metadata || {}
  const identityRows = [
    [app.t('hostname', 'Hostname'), metadataText(metadata.hostname) || item.host || '-'],
    [app.t('version', 'Version'), metadataText(metadata.version) || '-'],
    [app.t('operatingSystem', 'Operating system'), [metadataText(metadata.os), metadataText(metadata.arch)].filter(Boolean).join(' / ') || '-'],
    [app.t('ipAddresses', 'IP addresses'), metadataInlineListText(metadata.ip_addresses) || metadataText(metadata.last_client_ip) || '-'],
    [app.t('capabilities', 'Capabilities'), metadataInlineListText(metadata.capabilities) || '-'],
    [app.t('labels', 'Labels'), metadataInlineListText(metadata.labels) || metadataInlineListText(item.tags) || '-'],
  ]
  const metricRows = [
    [app.t('latency', 'Latency'), `${formatNumberValue(metadata.latency_ms)} ms`],
    ['CPU', formatPercentValueFromWhole(metadata.cpu_percent)],
    [app.t('memory', 'Memory'), `${formatBytesValue(metadata.memory_used_bytes)} / ${formatBytesValue(metadata.memory_total_bytes)} (${formatPercentValueFromWhole(metadata.memory_percent)})`],
    [app.t('disk', 'Disk'), `${formatBytesValue(metadata.disk_used_bytes)} / ${formatBytesValue(metadata.disk_total_bytes)} (${formatPercentValueFromWhole(metadata.disk_percent)})`],
    [app.t('networkReceive', 'Network received'), formatBytesValue(metadata.network_rx_bytes)],
    [app.t('networkTransmit', 'Network sent'), formatBytesValue(metadata.network_tx_bytes)],
    [app.t('activeSessions', 'Active sessions'), formatNumberValue(metadata.active_sessions)],
    [app.t('heartbeatCount', 'Heartbeat count'), formatNumberValue(metadata.heartbeat_count)],
  ]
  return (
    <>
      <div className='grid gap-3 sm:grid-cols-3'>
        <GatewayMetric label={app.t('online', 'Online')} value={formatNumberValue(summary?.online)} />
        <GatewayMetric label={app.t('offline', 'Offline')} value={formatNumberValue(summary?.offline)} />
        <GatewayMetric label={app.t('lastHeartbeat', 'Last heartbeat')} value={formatDate(metadataText(metadata.last_heartbeat_at))} />
      </div>
      <GatewayDetailSection title={app.t('gatewayIdentity', 'Gateway identity')} rows={identityRows} />
      <GatewayDetailSection title={app.t('resourceMetrics', 'Resource metrics')} rows={metricRows} />
      {metadataText(metadata.offline_reason) ? (
        <div className='rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive'>
          {app.t('offlineReason', 'Offline reason')}: {metadataText(metadata.offline_reason)}
        </div>
      ) : null}
    </>
  )
}

function GatewayGroupStatusContent({ status }: { status: GatewayGroupRuntimeStatus }) {
  const app = useApp()
  const members = status.members || []
  return (
    <>
      <div className='grid gap-3 sm:grid-cols-4'>
        <GatewayMetric label={app.t('selectionMode', 'Selection mode')} value={status.selection_mode || '-'} />
        <GatewayMetric label={app.t('members', 'Members')} value={formatNumberValue(members.length)} />
        <GatewayMetric label={app.t('online', 'Online')} value={formatNumberValue(status.online)} />
        <GatewayMetric label={app.t('offline', 'Offline')} value={formatNumberValue(status.offline)} />
      </div>
      <GatewayDetailSection
        title={app.t('routingRequirements', 'Routing requirements')}
        rows={[
          [app.t('selectedGateway', 'Selected gateway'), status.selected_gateway?.name || status.selected_gateway_id || '-'],
          [app.t('requiredLabels', 'Required labels'), (status.required_labels || []).join(', ') || '-'],
          [app.t('requiredCapabilities', 'Required capabilities'), (status.required_capabilities || []).join(', ') || '-'],
          [app.t('configuredMembers', 'Configured members'), (status.member_ids || []).join(', ') || '-'],
        ]}
      />
      <section className='grid gap-2'>
        <h3 className='text-sm font-semibold'>{app.t('gatewayMembers', 'Gateway members')}</h3>
        <div className='overflow-x-auto rounded-lg border border-border'>
          <table className='w-full min-w-[680px] text-left text-xs'>
            <thead className='bg-muted/50 text-muted-foreground'>
              <tr>
                <th className='px-3 py-2 font-medium'>{app.t('name', 'Name')}</th>
                <th className='px-3 py-2 font-medium'>{app.t('status', 'Status')}</th>
                <th className='px-3 py-2 font-medium'>{app.t('address', 'Address')}</th>
                <th className='px-3 py-2 font-medium'>{app.t('latency', 'Latency')}</th>
                <th className='px-3 py-2 font-medium'>{app.t('activeSessions', 'Active sessions')}</th>
                <th className='px-3 py-2 font-medium'>{app.t('capabilities', 'Capabilities')}</th>
                <th className='px-3 py-2 font-medium'>{app.t('lastHeartbeat', 'Last heartbeat')}</th>
              </tr>
            </thead>
            <tbody className='divide-y divide-border'>
              {members.map((member) => (
                <tr key={`${member.collection}:${member.id}`} className={member.id === status.selected_gateway_id ? 'bg-primary/5' : undefined}>
                  <td className='px-3 py-2 font-medium'>{member.name || member.id}</td>
                  <td className='px-3 py-2'><Badge tone={member.online ? 'success' : 'warning'}>{member.status || (member.online ? 'online' : 'offline')}</Badge></td>
                  <td className='px-3 py-2 font-mono'>{member.host ? `${member.host}${member.port ? `:${member.port}` : ''}` : '-'}</td>
                  <td className='px-3 py-2 font-mono'>{formatNumberValue(member.latency_ms)} ms</td>
                  <td className='px-3 py-2 font-mono'>{formatNumberValue(member.active_sessions)}</td>
                  <td className='px-3 py-2'>{(member.capabilities || []).join(', ') || '-'}</td>
                  <td className='px-3 py-2'>{formatDate(member.last_heartbeat_at || '')}</td>
                </tr>
              ))}
              {members.length === 0 ? (
                <tr><td colSpan={7} className='px-3 py-6 text-center text-muted-foreground'>{app.t('noData', 'No data')}</td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
    </>
  )
}

function GatewayMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className='min-w-0 rounded-lg border border-border bg-muted/20 p-3'>
      <div className='text-xs text-muted-foreground'>{label}</div>
      <div className='mt-1 truncate text-sm font-semibold' title={value}>{value || '-'}</div>
    </div>
  )
}

function GatewayDetailSection({ title, rows }: { title: string; rows: string[][] }) {
  return (
    <section className='grid gap-2'>
      <h3 className='text-sm font-semibold'>{title}</h3>
      <dl className='grid gap-x-4 gap-y-2 rounded-lg border border-border bg-muted/20 p-3 sm:grid-cols-2'>
        {rows.map(([label, value]) => (
          <div key={label} className='grid min-w-0 grid-cols-[minmax(7rem,auto)_minmax(0,1fr)] gap-3 text-xs'>
            <dt className='text-muted-foreground'>{label}</dt>
            <dd className='break-words text-right font-medium'>{value || '-'}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}

function AgentGatewayTokenDialog({ item, onClose, canIssueToken }: { item: PlatformItem; onClose: () => void; canIssueToken: boolean }) {
  const app = useApp()
  const [loading, setLoading] = useState(true)
  const [token, setToken] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [error, setError] = useState('')

  useEffect(() => {
    if (!canIssueToken) {
      setLoading(false)
      setError(app.t('permissionDenied', 'Permission denied'))
      return
    }
    let alive = true
    const issue = async () => {
      setLoading(true)
      setError('')
      setExpiresAt('')
      try {
        const data = await apiRequest<{ registration_token: string; gateway_id: string; expires_at?: string }>(`/api/admin/agent-gateways/${item.id}/token`, {
          method: 'POST',
          body: '{}',
        })
        if (!alive) return
        setToken(data.registration_token || '')
        setExpiresAt(data.expires_at || '')
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
  }, [app, canIssueToken, item.id])

  const server = window.location.origin
  const agentName = item.name || 'gateway-01'
  const linuxCommand = `OPENWEBSERVERMANAGER_AGENT_TOKEN=${quotePOSIXShell(token)} ./openwebservermanager-agent --server ${quotePOSIXShell(server)} --name ${quotePOSIXShell(agentName)}`
  const windowsCommand = `$env:OPENWEBSERVERMANAGER_AGENT_TOKEN = ${quotePowerShell(token)}; .\\openwebservermanager-agent.exe --server ${quotePowerShell(server)} --name ${quotePowerShell(agentName)}`

  const copy = async (value: string, message = '已复制') => {
    try {
      await copyText(value)
      app.showToast(message)
    } catch (error) {
      app.handleApiError(error)
    }
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
            <Field label={app.t('expiresAt', 'Expires at')}><Input readOnly value={formatDate(expiresAt)} /></Field>
            <div className='grid gap-3'>
              {[
                [app.t('agentLinuxCommand', 'Linux / macOS'), linuxCommand],
                [app.t('agentWindowsCommand', 'Windows PowerShell'), windowsCommand],
              ].map(([label, command]) => (
                <div key={label} className='rounded-lg border border-border bg-background/70 p-3'>
                  <div className='mb-2 flex items-center justify-between gap-2'>
                    <span className='text-xs font-medium text-muted-foreground'>{label}</span>
                    <Button size='sm' variant='ghost' onClick={() => void copy(command, app.t('agentCommandCopied', 'Agent command copied'))}>
                      <Copy className='size-3.5' />
                      {app.t('copyCommand', 'Copy command')}
                    </Button>
                  </div>
                  <pre className='overflow-auto rounded-md bg-muted p-3 text-xs'>{command}</pre>
                </div>
              ))}
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

function CertificateCreateDialog({ onClose, canSubmit }: { onClose: () => void; canSubmit: boolean }) {
  const app = useApp()
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [dns, setDNS] = useState('')
  const [ip, setIP] = useState('')
  const [days, setDays] = useState('365')
  const [saving, setSaving] = useState(false)

  const submit = async () => {
    if (!canSubmit) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
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
          <Button variant='primary' onClick={() => void submit()} disabled={saving || !canSubmit || !domain.trim()}>
            <Save className='size-4' />
            {saving ? '生成中' : '生成'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function CertificateUploadDialog({ onClose, canUpload }: { onClose: () => void; canUpload: boolean }) {
  const app = useApp()
  const [name, setName] = useState('')
  const [certificateFile, setCertificateFile] = useState<File | null>(null)
  const [privateKeyFile, setPrivateKeyFile] = useState<File | null>(null)
  const [chainFile, setChainFile] = useState<File | null>(null)
  const [saving, setSaving] = useState(false)

  const submit = async () => {
    if (!canUpload) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    if (!certificateFile) return
    setSaving(true)
    try {
      const form = new FormData()
      form.set('name', name)
      form.set('certificate', certificateFile)
      if (privateKeyFile) form.set('private_key', privateKeyFile)
      if (chainFile) form.set('chain', chainFile)
      const response = await fetch('/api/admin/certificates/upload', {
        method: 'POST',
        credentials: 'same-origin',
        body: form,
      })
      const payload = (await response.json().catch(() => ({}))) as { error?: string; setup_required?: boolean }
      if (!response.ok) {
        throw new ApiError(payload.error || response.statusText, response.status, Boolean(payload.setup_required))
      }
      await app.refresh(true)
      app.showToast('证书已上传')
      onClose()
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title='上传证书' description='上传 PEM 格式证书和可选私钥，服务端会校验证书与私钥是否匹配，并解析过期时间和 SAN。'>
      <div className='grid gap-4'>
        <div className='grid gap-3 sm:grid-cols-2'>
          <Field label='名称'><Input value={name} onChange={(event) => setName(event.currentTarget.value)} placeholder='production wildcard' /></Field>
          <Field label='证书 PEM'><Input type='file' accept='.crt,.cer,.pem' onChange={(event) => setCertificateFile(event.currentTarget.files?.[0] || null)} /></Field>
          <Field label='私钥 PEM'><Input type='file' accept='.key,.pem' onChange={(event) => setPrivateKeyFile(event.currentTarget.files?.[0] || null)} /></Field>
          <Field label='证书链 PEM'><Input type='file' accept='.crt,.cer,.pem' onChange={(event) => setChainFile(event.currentTarget.files?.[0] || null)} /></Field>
        </div>
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>取消</Button>
          <Button variant='primary' onClick={() => void submit()} disabled={saving || !canUpload || !certificateFile}>
            <Upload className='size-4' />
            {saving ? '上传中' : '上传'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function CertificateACMEDialog({ onClose, canUsePath }: { onClose: () => void; canUsePath: CanUsePath }) {
  const app = useApp()
  const canIssueACME = canUsePath('POST', '/api/admin/certificates/acme')
  const canReadDNSProviders = canUsePath('GET', '/api/admin/certificates/dns-providers')
  const [providers, setProviders] = useState<PlatformItem[]>([])
  const [name, setName] = useState('')
  const [domain, setDomain] = useState('')
  const [dns, setDNS] = useState('')
  const [ip, setIP] = useState('')
  const [email, setEmail] = useState('')
  const [days, setDays] = useState('90')
  const [issuanceMode, setIssuanceMode] = useState('letsencrypt')
  const [customDirectoryURL, setCustomDirectoryURL] = useState('')
  const [challengeType, setChallengeType] = useState('http-01')
  const [dnsProviderID, setDNSProviderID] = useState('')
  const [defaultCert, setDefaultCert] = useState(false)
  const [mtlsEnabled, setMTLSEnabled] = useState(false)
  const [saving, setSaving] = useState(false)
  const [issued, setIssued] = useState<PlatformItem | null>(null)

  useEffect(() => {
    if (!canReadDNSProviders) {
      setProviders([])
      setDNSProviderID('')
      return
    }
    let alive = true
    void apiRequest<{ items: PlatformItem[] }>('/api/admin/certificates/dns-providers')
      .then((data) => { if (alive) setProviders(data.items || []) })
      .catch(() => { if (alive) setProviders([]) })
    return () => { alive = false }
  }, [canReadDNSProviders])

  const submit = async () => {
    if (!canIssueACME) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    const directoryURL = issuanceMode === 'letsencrypt'
      ? 'https://acme-v02.api.letsencrypt.org/directory'
      : issuanceMode === 'staging'
        ? 'https://acme-staging-v02.api.letsencrypt.org/directory'
        : issuanceMode === 'local-ca'
          ? 'local-ca'
          : customDirectoryURL.trim()
    if (!directoryURL) return
    setSaving(true)
    try {
      const item = await apiRequest<PlatformItem>('/api/admin/certificates/acme', {
        method: 'POST',
        body: JSON.stringify({
          name,
          domain,
          dns: splitCSV(dns),
          ip: splitCSV(ip),
          email,
          days: Number(days) || 90,
          directory_url: directoryURL,
          challenge_type: issuanceMode === 'local-ca' ? 'http-01' : challengeType,
          dns_provider_id: challengeType === 'dns-01' ? dnsProviderID : undefined,
          default: defaultCert,
          mtls_enabled: mtlsEnabled,
        }),
      })
      setIssued(item)
      await app.refresh(true)
      app.showToast(app.t('certificateAcmeIssued', 'ACME certificate issued'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell
      open
      onOpenChange={(open) => !open && onClose()}
      title={app.t('certificateAcmeTitle', 'ACME certificate')}
      description={app.t('certificateAcmeDescription', 'Issue a certificate through ACME HTTP-01 or use the local CA mode for offline environments.')}
    >
      <div className='grid gap-4'>
        <div className='grid gap-3 sm:grid-cols-2'>
          <Field label={app.t('certificateName', 'Name')}><Input value={name} onChange={(event) => setName(event.currentTarget.value)} /></Field>
          <Field label={app.t('primaryDomain', 'Primary domain')}><Input value={domain} onChange={(event) => setDomain(event.currentTarget.value)} placeholder='example.com' /></Field>
          <Field label='DNS SAN'><Input value={dns} onChange={(event) => setDNS(event.currentTarget.value)} placeholder='www.example.com,api.example.com' /></Field>
          <Field label='IP SAN'><Input value={ip} onChange={(event) => setIP(event.currentTarget.value)} placeholder='127.0.0.1,10.0.0.1' /></Field>
          <Field label={app.t('email', 'Email')}><Input value={email} onChange={(event) => setEmail(event.currentTarget.value)} placeholder='ops@example.com' /></Field>
          <Field label={app.t('issuanceMode', 'Issuance mode')}>
            <Select value={issuanceMode} onChange={(event) => setIssuanceMode(event.currentTarget.value)}>
              <option value='letsencrypt'>{app.t('letsEncryptProduction', "Let's Encrypt production")}</option>
              <option value='staging'>{app.t('letsEncryptStaging', "Let's Encrypt staging")}</option>
              <option value='local-ca'>{app.t('localCA', 'Local CA')}</option>
              <option value='custom'>{app.t('customDirectory', 'Custom directory')}</option>
            </Select>
          </Field>
          {issuanceMode === 'custom' ? (
            <Field label={app.t('directoryURL', 'Directory URL')}><Input value={customDirectoryURL} onChange={(event) => setCustomDirectoryURL(event.currentTarget.value)} placeholder='https://acme.example.com/directory' /></Field>
          ) : null}
          {issuanceMode === 'local-ca' ? (
            <Field label={app.t('validityDays', 'Validity days')}><Input type='number' value={days} onChange={(event) => setDays(event.currentTarget.value)} /></Field>
          ) : null}
          {issuanceMode !== 'local-ca' ? (
            <Field label={app.t('challengeType', 'Challenge type')}>
              <Select value={challengeType} onChange={(event) => setChallengeType(event.currentTarget.value)}>
                <option value='http-01'>HTTP-01</option>
                <option value='dns-01'>DNS-01</option>
              </Select>
            </Field>
          ) : null}
          {issuanceMode !== 'local-ca' && challengeType === 'dns-01' ? (
            <Field label={app.t('dnsProvider', 'DNS provider')}>
              <Select value={dnsProviderID} onChange={(event) => setDNSProviderID(event.currentTarget.value)} disabled={!canReadDNSProviders}>
                <option value=''>{app.t('selectDNSProvider', 'Select DNS provider')}</option>
                {providers.map((provider) => <option key={provider.id} value={provider.id}>{provider.name}</option>)}
              </Select>
            </Field>
          ) : null}
        </div>
        <div className='grid gap-2 sm:grid-cols-2'>
          <CheckboxRow checked={defaultCert} onChange={setDefaultCert} label={app.t('setDefaultCertificate', 'Set as default certificate')} />
          <CheckboxRow checked={mtlsEnabled} onChange={setMTLSEnabled} label={app.t('enableMTLSFlag', 'Enable mTLS flag')} />
        </div>
        {issued ? (
          <div className='rounded-xl border border-border bg-background/60 p-3 text-sm'>
            <div className='flex items-center justify-between gap-3'>
              <strong>{issued.name}</strong>
              <Badge tone={statusTone(issued.status)}>{issued.status}</Badge>
            </div>
            <div className='mt-2 grid gap-1 text-xs text-muted-foreground'>
              <span>{app.t('issuanceMode', 'Issuance mode')}: {metadataText(issued.metadata?.acme_mode) || '-'}</span>
              <span>{app.t('expiresAt', 'Expires at')}: {formatDate(metadataText(issued.metadata?.expires_at))}</span>
            </div>
          </div>
        ) : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>{app.t('close', 'Close')}</Button>
          <Button variant='primary' onClick={() => void submit()} disabled={saving || !domain.trim() || !canIssueACME || (issuanceMode === 'custom' && !customDirectoryURL.trim()) || (issuanceMode !== 'local-ca' && challengeType === 'dns-01' && !dnsProviderID)}>
            <Save className='size-4' />
            {saving ? app.t('issuing', 'Issuing') : app.t('issue', 'Issue')}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function CertificateDNSProviderDialog({ onClose, canUsePath }: { onClose: () => void; canUsePath: CanUsePath }) {
  const app = useApp()
  const { confirm, confirmDialog } = useConfirmDialog()
  const canCreate = canUsePath('POST', '/api/admin/certificates/dns-providers')
  const canRead = canUsePath('GET', '/api/admin/certificates/dns-providers')
  const [providers, setProviders] = useState<PlatformItem[]>([])
  const [editing, setEditing] = useState<PlatformItem | null>(null)
  const [name, setName] = useState('')
  const [provider, setProvider] = useState('cloudflare')
  const [zone, setZone] = useState('')
  const [accessKeyID, setAccessKeyID] = useState('')
  const [token, setToken] = useState('')
  const [propagationTimeout, setPropagationTimeout] = useState('120')
  const [saving, setSaving] = useState(false)

  const loadProviders = async () => {
    if (!canRead) {
      setProviders([])
      return
    }
    const data = await apiRequest<{ items: PlatformItem[] }>('/api/admin/certificates/dns-providers')
    setProviders(data.items || [])
  }

  useEffect(() => {
    void loadProviders().catch((error) => app.handleApiError(error))
  }, [canRead])

  const resetForm = () => {
    setEditing(null)
    setName('')
    setProvider('cloudflare')
    setZone('')
    setAccessKeyID('')
    setToken('')
    setPropagationTimeout('120')
  }

  const editProvider = (item: PlatformItem) => {
    setEditing(item)
    setName(item.name || '')
    setProvider(metadataText(item.metadata?.provider) || 'cloudflare')
    setZone(metadataText(item.metadata?.zone))
    setAccessKeyID(metadataText(item.metadata?.access_key_id))
    setToken('')
    setPropagationTimeout(String(metadataNumber(item.metadata?.propagation_timeout_seconds) || 120))
  }

  const submit = async () => {
    const path = editing ? `/api/admin/certificates/dns-providers/${editing.id}` : '/api/admin/certificates/dns-providers'
    const method = editing ? 'PATCH' : 'POST'
    if (!canUsePath(method, path)) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setSaving(true)
    try {
      await apiRequest(path, {
        method,
        body: JSON.stringify({
          name,
          provider,
          zone,
          access_key_id: provider === 'alidns' ? accessKeyID : undefined,
          token: token || undefined,
          propagation_timeout_seconds: Number(propagationTimeout) || 120,
        }),
      })
      await loadProviders()
      await app.refresh(true)
      app.showToast(app.t('dnsProviderSaved', 'DNS provider saved'))
      resetForm()
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  const deleteProvider = async (item: PlatformItem) => {
    const path = `/api/admin/certificates/dns-providers/${item.id}`
    if (!canUsePath('DELETE', path)) return
    const accepted = await confirm({
      title: app.t('deleteDNSProviderTitle', 'Delete DNS provider?'),
      description: app.t('deleteDNSProviderDescription', 'Certificates using this provider must be changed or removed first.'),
      confirmText: app.t('delete', 'Delete'),
      destructive: true,
    })
    if (!accepted) return
    try {
      await apiRequest(path, { method: 'DELETE' })
      await loadProviders()
      await app.refresh(true)
      if (editing?.id === item.id) resetForm()
      app.showToast(app.t('dnsProviderDeleted', 'DNS provider deleted'))
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const tokenPlaceholder = provider === 'cloudflare'
    ? 'Cloudflare API Token'
    : provider === 'dnspod'
      ? 'ID,Token'
      : 'AccessKeySecret'
  const canSubmit = editing
    ? canUsePath('PATCH', `/api/admin/certificates/dns-providers/${editing.id}`)
    : canCreate
  const providerChanged = Boolean(editing && provider !== (metadataText(editing.metadata?.provider) || 'cloudflare'))

  return (
    <>
      <DialogShell
        open
        onOpenChange={(open) => !open && onClose()}
        title={app.t('dnsProvider', 'DNS provider')}
        description={app.t('dnsProviderDescription', 'Configure credentials used to create and remove ACME DNS-01 TXT records.')}
      >
        <div className='grid gap-5'>
          <div className='grid gap-3 sm:grid-cols-2'>
            <Field label={app.t('certificateName', 'Name')}><Input value={name} onChange={(event) => setName(event.currentTarget.value)} placeholder='Production DNS' /></Field>
            <Field label={app.t('provider', 'Provider')}>
              <Select value={provider} onChange={(event) => setProvider(event.currentTarget.value)}>
                <option value='cloudflare'>Cloudflare</option>
                <option value='alidns'>AliDNS</option>
                <option value='dnspod'>DNSPod</option>
              </Select>
            </Field>
            <Field label={app.t('dnsZone', 'DNS zone')}><Input value={zone} onChange={(event) => setZone(event.currentTarget.value)} placeholder='example.com' /></Field>
            {provider === 'alidns' ? (
              <Field label={app.t('accessKeyID', 'Access key ID')}><Input value={accessKeyID} onChange={(event) => setAccessKeyID(event.currentTarget.value)} /></Field>
            ) : null}
            <Field label={app.t('apiTokenOrSecret', 'API token or secret')}>
              <Input type='password' value={token} onChange={(event) => setToken(event.currentTarget.value)} placeholder={editing ? app.t('leaveBlankToKeepSecret', 'Leave blank to keep current secret') : tokenPlaceholder} />
            </Field>
            <Field label={app.t('propagationTimeout', 'Propagation timeout (seconds)')}><Input type='number' min='10' value={propagationTimeout} onChange={(event) => setPropagationTimeout(event.currentTarget.value)} /></Field>
          </div>
          <div className='flex justify-end gap-2'>
            {editing ? <Button variant='outline' onClick={resetForm}>{app.t('cancel', 'Cancel')}</Button> : null}
            <Button variant='primary' onClick={() => void submit()} disabled={saving || !canSubmit || !name.trim() || !zone.trim() || ((!editing || providerChanged) && !token.trim()) || (provider === 'alidns' && !accessKeyID.trim())}>
              <Save className='size-4' />
              {saving ? app.t('saving', 'Saving') : editing ? app.t('update', 'Update') : app.t('save', 'Save')}
            </Button>
          </div>
          {canRead ? (
            <div className='grid gap-2 border-t border-border pt-4'>
              <div className='text-sm font-medium'>{app.t('savedDNSProviders', 'Saved DNS providers')}</div>
              {providers.length ? providers.map((item) => (
                <div key={item.id} className='flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2'>
                  <div className='min-w-0'>
                    <div className='truncate text-sm font-medium'>{item.name}</div>
                    <div className='truncate text-xs text-muted-foreground'>{metadataText(item.metadata?.provider)} · {metadataText(item.metadata?.zone)}</div>
                  </div>
                  <div className='flex shrink-0 gap-1'>
                    {canUsePath('PATCH', `/api/admin/certificates/dns-providers/${item.id}`) ? (
                      <Button size='icon' variant='ghost' title={app.t('edit', 'Edit')} onClick={() => editProvider(item)}><Pencil className='size-4' /></Button>
                    ) : null}
                    {canUsePath('DELETE', `/api/admin/certificates/dns-providers/${item.id}`) ? (
                      <Button size='icon' variant='ghost' title={app.t('delete', 'Delete')} onClick={() => void deleteProvider(item)}><Trash2 className='size-4' /></Button>
                    ) : null}
                  </div>
                </div>
              )) : <div className='text-sm text-muted-foreground'>{app.t('none', 'None')}</div>}
            </div>
          ) : null}
        </div>
      </DialogShell>
      {confirmDialog}
    </>
  )
}

function CertificateMTLSDialog({ item, onClose, canSave }: { item: PlatformItem; onClose: () => void; canSave: boolean }) {
  const app = useApp()
  const [enabled, setEnabled] = useState(metadataBool(item.metadata?.mtls_enabled))
  const [clientCA, setClientCA] = useState('')
  const [saving, setSaving] = useState(false)

  const submit = async () => {
    if (!canSave) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setSaving(true)
    try {
      await apiRequest(`/api/admin/certificates/${item.id}/mtls`, {
        method: 'POST',
        body: JSON.stringify({ enabled, client_ca: clientCA || undefined }),
      })
      await app.refresh(true)
      app.showToast(app.t('mtlsSettingsSaved', 'mTLS settings saved'))
      onClose()
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} mTLS`} description='启用后可被 Web 资产反向代理作为上游客户端证书使用；可选客户端 CA PEM 会参与上游 TLS 校验。'>
      <div className='grid gap-4'>
        <CheckboxRow checked={enabled} onChange={setEnabled} label='启用 mTLS' />
        <Field label='Client CA PEM'><Textarea className='min-h-44 font-mono text-xs' value={clientCA} onChange={(event) => setClientCA(event.currentTarget.value)} placeholder='-----BEGIN CERTIFICATE-----' /></Field>
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>取消</Button>
          <Button variant='primary' onClick={() => void submit()} disabled={saving || !canSave}>
            <Save className='size-4' />
            {saving ? '保存中' : '保存'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function CertificateLogsDialog({ item, onClose, canRead }: { item: PlatformItem; onClose: () => void; canRead: boolean }) {
  const app = useApp()
  const [logs, setLogs] = useState<PlatformItem[]>([])

  const load = async () => {
    if (!canRead) {
      setLogs([])
      return
    }
    try {
      const data = await apiRequest<{ items: PlatformItem[] }>(`/api/admin/certificates/${item.id}/logs`)
      setLogs(data.items || [])
    } catch (error) {
      app.handleApiError(error)
    }
  }

  useEffect(() => {
    void load()
  }, [canRead, item.id])

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} 证书日志`} description='查看该证书的申请、签发、下载、默认切换和 mTLS 操作日志。'>
      <div className='grid gap-3'>
        <div className='flex justify-end'>
          <Button variant='outline' onClick={() => void load()} disabled={!canRead}><RefreshCw className='size-4' />刷新</Button>
        </div>
        {!canRead ? (
          <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>{app.t('permissionDenied', 'Permission denied')}</div>
        ) : logs.length ? logs.map((log) => (
          <article key={log.id} className='rounded-xl border border-border bg-background/60 p-3 text-sm'>
            <div className='flex items-center justify-between gap-3'>
              <strong>{log.name}</strong>
              <Badge tone={statusTone(log.status)}>{log.status}</Badge>
            </div>
            <p className='mt-2 text-xs text-muted-foreground'>{log.description || log.id}</p>
            <pre className='mt-3 overflow-auto rounded-lg bg-muted p-2 text-xs'>{JSON.stringify(log.metadata || {}, null, 2)}</pre>
          </article>
        )) : (
          <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>暂无证书日志。</div>
        )}
      </div>
    </DialogShell>
  )
}

function StorageFilesDialog({ item, onClose, canUsePath }: { item: PlatformItem; onClose: () => void; canUsePath: CanUsePath }) {
  const app = useApp()
  const { confirm, confirmDialog } = useConfirmDialog()
  const storageAPIPath = `/api/admin/storages/${item.id}`
  const canListFiles = canUsePath('GET', `${storageAPIPath}/files`)
  const canDeleteFiles = canUsePath('DELETE', `${storageAPIPath}/files`)
  const canDownloadFiles = canUsePath('GET', `${storageAPIPath}/files-download`)
  const canUploadFiles = canUsePath('POST', `${storageAPIPath}/files-upload`)
  const canWriteFiles = canUsePath('POST', `${storageAPIPath}/files-write`)
  const canCreateFolders = canUsePath('POST', `${storageAPIPath}/files-mkdir`)
  const canCopyFiles = canUsePath('POST', `${storageAPIPath}/files-copy`)
  const canRenameFiles = canUsePath('POST', `${storageAPIPath}/files-rename`)
  const canEditTextFiles = canDownloadFiles && canWriteFiles
  const [path, setPath] = useState('.')
  const [entries, setEntries] = useState<StorageEntry[]>([])
  const [usage, setUsage] = useState<StorageUsage | null>(null)
  const [loading, setLoading] = useState(false)
  const [folderName, setFolderName] = useState('')
  const [filePath, setFilePath] = useState('')
  const [fileContent, setFileContent] = useState('')
  const [copySource, setCopySource] = useState('')
  const [copyDestination, setCopyDestination] = useState('')
  const [copyOverwrite, setCopyOverwrite] = useState(false)
  const [renameSource, setRenameSource] = useState('')
  const [renameDestination, setRenameDestination] = useState('')
  const [renameOverwrite, setRenameOverwrite] = useState(false)
  const [editingFilePath, setEditingFilePath] = useState('')
  const [textLoadingPath, setTextLoadingPath] = useState('')
  const [uploadFileItem, setUploadFileItem] = useState<File | null>(null)
  const [uploadInputKey, setUploadInputKey] = useState(0)

  const load = async (target = path) => {
    if (!canListFiles) return
    setLoading(true)
    try {
      const data = await apiRequest<{ path: string; entries: StorageEntry[]; usage?: StorageUsage }>(`${storageAPIPath}/files?path=${encodeURIComponent(target)}`)
      setPath(data.path || '.')
      setEntries(sortStorageEntries(data.entries || []))
      setUsage(data.usage || null)
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
    if (!canCreateFolders) return
    try {
      await apiRequest(`${storageAPIPath}/files-mkdir`, {
        method: 'POST',
        body: JSON.stringify({ path: resolveStoragePath(path, folderName) }),
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
    if (!canWriteFiles) return
    try {
      await apiRequest(`${storageAPIPath}/files-write`, {
        method: 'POST',
        body: JSON.stringify({ path: resolveStoragePath(path, filePath), content: fileContent }),
      })
      setFilePath('')
      setFileContent('')
      setEditingFilePath('')
      await load()
      await app.refresh(true)
      app.showToast('文件已写入')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const uploadSelectedFile = async () => {
    if (!canUploadFiles || !uploadFileItem) return
    try {
      const form = new FormData()
      form.set('path', path === '.' ? '' : path)
      form.set('file', uploadFileItem)
      const response = await fetch(`${storageAPIPath}/files-upload`, {
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
    if (!canDeleteFiles) return
    const confirmed = await confirm({
      title: `删除 ${entry.path}?`,
      description: '文件或目录删除后不可恢复。',
      confirmText: '删除',
      destructive: true,
    })
    if (!confirmed) return
    try {
      await apiRequest(`${storageAPIPath}/files?path=${encodeURIComponent(entry.path)}`, { method: 'DELETE' })
      await load()
      await app.refresh(true)
      app.showToast('文件已删除')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const downloadEntry = async (entry: StorageEntry) => {
    if (!canDownloadFiles) return
    try {
      await downloadResponse(`${storageAPIPath}/files-download?path=${encodeURIComponent(entry.path)}`, entry.name)
      app.showToast('文件已下载')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const copyEntry = async () => {
    if (!canCopyFiles) return
    try {
      await apiRequest(`${storageAPIPath}/files-copy`, {
        method: 'POST',
        body: JSON.stringify({
          path: resolveStoragePath(path, copySource),
          destination: resolveStoragePath(path, copyDestination),
          overwrite: copyOverwrite,
        }),
      })
      setCopySource('')
      setCopyDestination('')
      setCopyOverwrite(false)
      await load()
      await app.refresh(true)
      app.showToast('文件已复制')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const renameEntry = async () => {
    if (!canRenameFiles) return
    try {
      await apiRequest(`${storageAPIPath}/files-rename`, {
        method: 'POST',
        body: JSON.stringify({
          path: resolveStoragePath(path, renameSource),
          destination: resolveStoragePath(path, renameDestination),
          overwrite: renameOverwrite,
        }),
      })
      setRenameSource('')
      setRenameDestination('')
      setRenameOverwrite(false)
      await load()
      await app.refresh(true)
      app.showToast('文件已重命名')
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const prefillCopyEntry = (entry: StorageEntry) => {
    if (!canCopyFiles) return
    setCopySource(rootStoragePath(entry.path))
    setCopyDestination(rootStoragePath(siblingStoragePath(entry.path, copiedStorageName(entry.name, entry.is_dir))))
    setCopyOverwrite(false)
  }

  const prefillRenameEntry = (entry: StorageEntry) => {
    if (!canRenameFiles) return
    setRenameSource(rootStoragePath(entry.path))
    setRenameDestination(rootStoragePath(siblingStoragePath(entry.path, renamedStorageName(entry.name, entry.is_dir))))
    setRenameOverwrite(false)
  }

  const editTextEntry = async (entry: StorageEntry) => {
    if (!canEditTextFiles) return
    setTextLoadingPath(entry.path)
    try {
      const text = await fetchStorageText(`${storageAPIPath}/files-download?path=${encodeURIComponent(entry.path)}`)
      setFilePath(rootStoragePath(entry.path))
      setFileContent(text)
      setEditingFilePath(entry.path)
      app.showToast('文件内容已载入')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setTextLoadingPath('')
    }
  }

  const usagePercent = usage?.limit_bytes ? Math.min(100, Math.round((numberValue(usage.bytes) / numberValue(usage.limit_bytes)) * 100)) : 0

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} 文件`} description='浏览文件盘，创建目录，写入、下载和删除文件，操作会写入文件日志。'>
      <div className='grid gap-4'>
        <div className='grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto_auto]'>
          <Input value={path} onChange={(event) => setPath(event.currentTarget.value)} />
          <Button variant='outline' onClick={() => void load()} disabled={loading}><RefreshCw className='size-4' />打开</Button>
          <Button variant='outline' onClick={() => void load(parentStoragePath(path))} disabled={path === '.' || loading}>上级</Button>
        </div>
        {usage ? (
          <div className='grid gap-2 rounded-xl border border-border bg-background/60 p-3 text-sm'>
            <div className='flex flex-wrap items-center justify-between gap-2'>
              <span className='font-medium'>
                已用 {formatBytesValue(usage.bytes)}
                {usage.limit_bytes ? ` / ${formatBytesValue(usage.limit_bytes)}` : ''}
              </span>
              <span className='text-xs text-muted-foreground'>
                {formatNumberValue(usage.files)} 文件 · {formatNumberValue(usage.dirs)} 目录
                {usage.limit_bytes ? ` · 剩余 ${formatBytesValue(usage.available_bytes || 0)}` : ''}
              </span>
            </div>
            {usage.limit_bytes ? (
              <div className='h-2 overflow-hidden rounded-full bg-muted'>
                <div className='h-full rounded-full bg-primary transition-all' style={{ width: `${usagePercent}%` }} />
              </div>
            ) : null}
          </div>
        ) : null}
        <div className='grid gap-2 rounded-xl border border-border bg-background/60 p-3'>
          {entries.length ? entries.map((entry) => (
            <div key={entry.path} className='grid gap-2 rounded-lg border border-border bg-card p-2 text-sm sm:grid-cols-[minmax(0,1fr)_5rem_minmax(0,auto)] sm:items-center'>
              <button className='min-w-0 text-left' onClick={() => entry.is_dir && void load(entry.path)}>
                <span className='block truncate font-medium'>{entry.is_dir ? '目录' : '文件'} / {entry.name}</span>
                <span className='block truncate text-xs text-muted-foreground'>{entry.path} · {entry.size} B · {formatDate(entry.modified)}</span>
              </button>
              <Badge tone={entry.is_dir ? 'neutral' : 'success'}>{entry.is_dir ? 'dir' : 'file'}</Badge>
              <div className='flex flex-wrap justify-end gap-1.5'>
                {!entry.is_dir ? (
                  <>
                    {canDownloadFiles ? (
                      <Button size='sm' variant='outline' onClick={() => void downloadEntry(entry)}><Download className='size-3.5' />下载</Button>
                    ) : null}
                    {canEditTextFiles ? (
                      <Button size='sm' variant='outline' onClick={() => void editTextEntry(entry)} disabled={textLoadingPath === entry.path}><Pencil className='size-3.5' />编辑</Button>
                    ) : null}
                  </>
                ) : null}
                {canCopyFiles ? (
                  <Button size='sm' variant='outline' onClick={() => prefillCopyEntry(entry)}><Copy className='size-3.5' />复制</Button>
                ) : null}
                {canRenameFiles ? (
                  <Button size='sm' variant='outline' onClick={() => prefillRenameEntry(entry)}><MoveRight className='size-3.5' />重命名</Button>
                ) : null}
                {canDeleteFiles ? (
                  <Button size='sm' variant='destructive' onClick={() => void deleteEntry(entry)}><Trash2 className='size-3.5' />删除</Button>
                ) : null}
              </div>
            </div>
          )) : (
            <div className='rounded-lg border border-dashed border-border p-6 text-sm text-muted-foreground'>{loading ? '加载中' : '当前目录为空'}</div>
          )}
        </div>
        {canCreateFolders ? (
          <div className='grid gap-3 sm:grid-cols-[minmax(0,1fr)_auto]'>
            <Input placeholder='新目录名' value={folderName} onChange={(event) => setFolderName(event.currentTarget.value)} />
            <Button variant='outline' onClick={() => void createFolder()} disabled={!folderName.trim()}><FolderPlus className='size-4' />创建目录</Button>
          </div>
        ) : null}
        {canUploadFiles ? (
          <div className='grid gap-3 rounded-xl border border-border bg-background/60 p-3 sm:grid-cols-[minmax(0,1fr)_auto]'>
            <Input key={uploadInputKey} type='file' onChange={(event) => setUploadFileItem(event.currentTarget.files?.[0] || null)} />
            <Button variant='outline' onClick={() => void uploadSelectedFile()} disabled={!uploadFileItem}>
              <Upload className='size-4' />
              上传
            </Button>
          </div>
        ) : null}
        {canCopyFiles || canRenameFiles ? (
          <div className='grid gap-3 rounded-xl border border-border bg-background/60 p-3'>
            {canCopyFiles ? (
              <>
                <div className='grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]'>
                  <Input placeholder='复制源，当前目录相对路径或 /docs/a.txt' value={copySource} onChange={(event) => setCopySource(event.currentTarget.value)} />
                  <Input placeholder='复制到，当前目录相对路径或 /docs/b.txt' value={copyDestination} onChange={(event) => setCopyDestination(event.currentTarget.value)} />
                  <Button variant='outline' onClick={() => void copyEntry()} disabled={!copySource.trim() || !copyDestination.trim()}>
                    <Copy className='size-4' />
                    复制
                  </Button>
                </div>
                <CheckboxRow checked={copyOverwrite} onChange={setCopyOverwrite} label='复制时覆盖已存在的目标' />
              </>
            ) : null}
            {canRenameFiles ? (
              <>
                <div className='grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto]'>
                  <Input placeholder='重命名源，当前目录相对路径或 /docs/b.txt' value={renameSource} onChange={(event) => setRenameSource(event.currentTarget.value)} />
                  <Input placeholder='改为，当前目录相对路径或 /docs/c.txt' value={renameDestination} onChange={(event) => setRenameDestination(event.currentTarget.value)} />
                  <Button variant='outline' onClick={() => void renameEntry()} disabled={!renameSource.trim() || !renameDestination.trim()}>
                    <MoveRight className='size-4' />
                    重命名
                  </Button>
                </div>
                <CheckboxRow checked={renameOverwrite} onChange={setRenameOverwrite} label='重命名时覆盖已存在的目标' />
              </>
            ) : null}
          </div>
        ) : null}
        {canWriteFiles ? (
          <div className='grid gap-3'>
            {editingFilePath ? (
              <div className='flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-muted/30 px-3 py-2 text-xs text-muted-foreground'>
                <span className='truncate'>正在编辑 /{editingFilePath}</span>
                <Button size='sm' variant='outline' onClick={() => { setEditingFilePath(''); setFilePath(''); setFileContent('') }}>清空编辑</Button>
              </div>
            ) : null}
            <Input placeholder='文件名，当前目录相对路径或 /notes/readme.txt' value={filePath} onChange={(event) => setFilePath(event.currentTarget.value)} />
            <Textarea placeholder='文件内容' value={fileContent} onChange={(event) => setFileContent(event.currentTarget.value)} />
            <div className='flex justify-end gap-2'>
              <Button variant='outline' onClick={onClose}>关闭</Button>
              <Button variant='primary' onClick={() => void writeFile()} disabled={!filePath.trim()}><Save className='size-4' />写入文件</Button>
            </div>
          </div>
        ) : (
          <div className='flex justify-end'>
            <Button variant='outline' onClick={onClose}>关闭</Button>
          </div>
        )}
        {canDeleteFiles ? confirmDialog : null}
      </div>
    </DialogShell>
  )
}

function TaskLogsDialog({ item, onClose, canRead }: { item: PlatformItem; onClose: () => void; canRead: boolean }) {
  const app = useApp()
  const [logs, setLogs] = useState<PlatformItem[]>([])

  const load = async () => {
    if (!canRead) {
      setLogs([])
      return
    }
    try {
      const data = await apiRequest<{ items: PlatformItem[] }>(`/api/admin/scheduled-tasks/${item.id}/logs`)
      setLogs(data.items || [])
    } catch (error) {
      app.handleApiError(error)
    }
  }

  useEffect(() => {
    void load()
  }, [canRead, item.id])

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} 运行日志`} description='查看该定时任务的手动和自动运行记录。'>
      <div className='grid gap-3'>
        <div className='flex justify-end'>
          <Button variant='outline' onClick={() => void load()} disabled={!canRead}><RefreshCw className='size-4' />刷新</Button>
        </div>
        {!canRead ? (
          <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>{app.t('permissionDenied', 'Permission denied')}</div>
        ) : logs.length ? logs.map((log) => (
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

function SSHExecDialog({ item, onClose, requestAccessMFACode }: { item: PlatformItem; onClose: () => void; requestAccessMFACode: RequestAccessMFACode }) {
  const app = useApp()
  const [command, setCommand] = useState(stringValue(item.metadata?.command) || 'uptime')
  const [timeoutSeconds, setTimeoutSeconds] = useState('30')
  const [result, setResult] = useState<SSHExecResult | null>(null)
  const [running, setRunning] = useState(false)

  const execute = async () => {
    setRunning(true)
    try {
      const payload = {
        command,
        timeout_seconds: Number(timeoutSeconds) || 30,
      }
      const runCommand = (mfaCode = '') => apiRequest<SSHExecResult>(`/api/access/ssh/${item.id}/exec`, {
        method: 'POST',
        body: JSON.stringify(mfaCode ? { ...payload, mfa_code: mfaCode } : payload),
      })
      let data: SSHExecResult
      try {
        data = await runCommand()
      } catch (error) {
        if (!isAccessMFARequiredError(error)) throw error
        const mfaCode = await requestAccessMFACode()
        if (!mfaCode) return
        data = await runCommand(mfaCode)
      }
      setResult(data)
      await app.refresh(true)
      app.showToast('SSH command executed')
    } catch (error) {
      if (error instanceof ApiError && error.status === 403 && error.data) {
        setResult(error.data as SSHExecResult)
        await app.refresh(true)
        return
      }
      app.handleApiError(error)
    } finally {
      setRunning(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} Exec`} description='Run a non-interactive SSH command. Output, exit code, risk level, and duration are written to remote command logs.'>
      <div className='grid gap-4'>
        <Field label='Command'><Textarea className='min-h-32 font-mono text-xs' value={command} onChange={(event) => setCommand(event.currentTarget.value)} /></Field>
        <Field label='Timeout seconds'><Input type='number' min={1} max={600} value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(event.currentTarget.value)} /></Field>
        {result ? (
          <div className='rounded-xl border border-border bg-background/60 p-3'>
            <div className='flex flex-wrap items-center justify-between gap-2 text-sm'>
              <strong>{result.status}</strong>
              <div className='flex flex-wrap items-center gap-2'>
                <Badge tone={result.blocked ? 'danger' : statusTone(result.status)}>{result.action || result.status}</Badge>
                <Badge tone={result.risk === 'high' ? 'danger' : result.risk === 'normal' ? 'neutral' : 'warning'}>{result.risk || 'normal'}</Badge>
                <span className='font-mono text-xs text-muted-foreground'>exit {result.exit_code} / {result.duration_ms} ms</span>
              </div>
            </div>
            {result.error ? <p className='mt-2 text-xs text-destructive'>{result.error}</p> : null}
            <div className='mt-3 grid gap-3 md:grid-cols-2'>
              <pre className='min-h-28 overflow-auto rounded-lg bg-muted p-2 text-xs'>{result.stdout || '(stdout empty)'}</pre>
              <pre className='min-h-28 overflow-auto rounded-lg bg-muted p-2 text-xs'>{result.stderr || '(stderr empty)'}</pre>
            </div>
          </div>
        ) : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>Close</Button>
          <Button variant='primary' onClick={() => void execute()} disabled={running || !command.trim()}>
            <TerminalSquare className='size-4' />
            {running ? 'Running...' : 'Run'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function SQLWorkOrderDecisionDialog({
  item,
  decision,
  onClose,
  canSubmit,
}: {
  item: PlatformItem
  decision: 'approve' | 'reject'
  onClose: () => void
  canSubmit: boolean
}) {
  const app = useApp()
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const approving = decision === 'approve'

  const submit = async () => {
    if (!canSubmit) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setSaving(true)
    try {
      await apiRequest(`/api/admin/sql-work-orders/${item.id}/${approving ? 'approve' : 'reject'}`, {
        method: 'POST',
        body: JSON.stringify({ note }),
      })
      await app.refresh(true)
      app.showToast(approving ? 'SQL 工单已批准' : 'SQL 工单已拒绝')
      onClose()
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell
      open
      onOpenChange={(open) => !open && onClose()}
      title={`${approving ? '批准' : '拒绝'} ${item.name || item.id}`}
      description='审批意见会写入 SQL 工单元数据，并保留在操作审计中。'
      compact
    >
      <div className='grid gap-4'>
        <div className='rounded-lg border border-border bg-muted/20 p-3 text-xs'>
          <div className='font-medium text-foreground'>SQL</div>
          <pre className='mt-2 max-h-36 overflow-auto whitespace-pre-wrap rounded-md bg-background p-2 font-mono'>{metadataText(item.metadata?.sql) || '-'}</pre>
          {metadataText(item.metadata?.reason) ? (
            <p className='mt-2 text-muted-foreground'>申请原因：{metadataText(item.metadata?.reason)}</p>
          ) : null}
        </div>
        <Field label={approving ? '审批意见' : '拒绝原因'}>
          <Textarea
            autoFocus
            className='min-h-28'
            value={note}
            onChange={(event) => setNote(event.currentTarget.value)}
            placeholder={approving ? '例如：窗口期内允许执行，已确认影响范围。' : '例如：缺少回滚方案或影响范围说明。'}
          />
        </Field>
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>取消</Button>
          <Button variant={approving ? 'primary' : 'destructive'} onClick={() => void submit()} disabled={saving || !canSubmit}>
            {saving ? '提交中' : approving ? '批准' : '拒绝'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function SQLWorkOrderDecisionSummary({ item }: { item: PlatformItem }) {
  const approvedBy = metadataText(item.metadata?.approved_by)
  const rejectedBy = metadataText(item.metadata?.rejected_by)
  const approvalNote = metadataText(item.metadata?.approval_note)
  const rejectionNote = metadataText(item.metadata?.rejection_note)
  if (approvedBy) {
    return (
      <div className='grid max-w-56 gap-1 text-xs'>
        <span>批准：{approvedBy}</span>
        <span className='text-muted-foreground'>{formatDate(metadataText(item.metadata?.approved_at))}</span>
        {approvalNote ? <span className='truncate text-muted-foreground'>{approvalNote}</span> : null}
      </div>
    )
  }
  if (rejectedBy) {
    return (
      <div className='grid max-w-56 gap-1 text-xs'>
        <span>拒绝：{rejectedBy}</span>
        <span className='text-muted-foreground'>{formatDate(metadataText(item.metadata?.rejected_at))}</span>
        {rejectionNote ? <span className='truncate text-muted-foreground'>{rejectionNote}</span> : null}
      </div>
    )
  }
  return <span className='text-xs text-muted-foreground'>待审批</span>
}

function SQLWorkOrderExecutionSummary({ item }: { item: PlatformItem }) {
  const executedBy = metadataText(item.metadata?.executed_by)
  const error = metadataText(item.metadata?.execution_error)
  const logID = metadataText(item.metadata?.sql_log_id)
  if (error) {
    return <span className='block max-w-56 truncate text-xs text-destructive'>{error}</span>
  }
  if (executedBy || logID) {
    return (
      <div className='grid max-w-56 gap-1 text-xs'>
        <span>执行：{executedBy || '-'}</span>
        <span className='text-muted-foreground'>{formatDate(metadataText(item.metadata?.executed_at))}</span>
        <span className='text-muted-foreground'>
          {formatNumberValue(item.metadata?.rows_affected)} rows / {formatNumberValue(item.metadata?.duration_ms)} ms
        </span>
      </div>
    )
  }
  return <span className='text-xs text-muted-foreground'>未执行</span>
}

function CommandApprovalDecisionDialog({
  item,
  decision,
  onClose,
  canSubmit,
}: {
  item: PlatformItem
  decision: 'approve' | 'reject'
  onClose: () => void
  canSubmit: boolean
}) {
  const app = useApp()
  const [note, setNote] = useState('')
  const [saving, setSaving] = useState(false)
  const approving = decision === 'approve'

  const submit = async () => {
    if (!canSubmit) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setSaving(true)
    try {
      await apiRequest(`/api/admin/command-approvals/${item.id}/${approving ? 'approve' : 'reject'}`, {
        method: 'POST',
        body: JSON.stringify({ note }),
      })
      await app.refresh(true)
      app.showToast(approving ? '命令审批已批准' : '命令审批已拒绝')
      onClose()
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSaving(false)
    }
  }

  return (
    <DialogShell
      open
      onOpenChange={(open) => !open && onClose()}
      title={`${approving ? '批准' : '拒绝'} ${item.name || item.id}`}
      description='审批意见会写入命令审批记录，并保留在操作审计中。'
      compact
    >
      <div className='grid gap-4'>
        <div className='rounded-lg border border-border bg-muted/20 p-3 text-xs'>
          <div className='font-medium text-foreground'>命令</div>
          <pre className='mt-2 max-h-36 overflow-auto whitespace-pre-wrap rounded-md bg-background p-2 font-mono'>{metadataText(item.metadata?.command) || '-'}</pre>
          <p className='mt-2 text-muted-foreground'>
            规则：{metadataText(item.metadata?.rule_name) || '-'} / 风险：{metadataText(item.metadata?.risk) || '-'}
          </p>
        </div>
        <Field label={approving ? '审批意见' : '拒绝原因'}>
          <Textarea
            autoFocus
            className='min-h-28'
            value={note}
            onChange={(event) => setNote(event.currentTarget.value)}
            placeholder={approving ? '已确认维护窗口和命令影响范围。' : '缺少回滚方案或影响范围不明确。'}
          />
        </Field>
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>取消</Button>
          <Button variant={approving ? 'primary' : 'destructive'} onClick={() => void submit()} disabled={saving || !canSubmit}>
            {saving ? '提交中' : approving ? '批准' : '拒绝'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function CommandApprovalDecisionSummary({ item }: { item: PlatformItem }) {
  const approvedBy = metadataText(item.metadata?.approved_by)
  const rejectedBy = metadataText(item.metadata?.rejected_by)
  const approvalNote = metadataText(item.metadata?.approval_note)
  const rejectionNote = metadataText(item.metadata?.rejection_note)
  if (approvedBy) {
    return (
      <div className='grid max-w-56 gap-1 text-xs'>
        <span>批准：{approvedBy}</span>
        <span className='text-muted-foreground'>{formatDate(metadataText(item.metadata?.approved_at))}</span>
        {approvalNote ? <span className='truncate text-muted-foreground'>{approvalNote}</span> : null}
      </div>
    )
  }
  if (rejectedBy) {
    return (
      <div className='grid max-w-56 gap-1 text-xs'>
        <span>拒绝：{rejectedBy}</span>
        <span className='text-muted-foreground'>{formatDate(metadataText(item.metadata?.rejected_at))}</span>
        {rejectionNote ? <span className='truncate text-muted-foreground'>{rejectionNote}</span> : null}
      </div>
    )
  }
  return <span className='text-xs text-muted-foreground'>待审批</span>
}

function CommandApprovalExecutionSummary({ item }: { item: PlatformItem }) {
  const executedBy = metadataText(item.metadata?.executed_by)
  const error = metadataText(item.metadata?.execution_error) || metadataText(item.metadata?.error)
  if (error) {
    return <span className='block max-w-56 truncate text-xs text-destructive'>{error}</span>
  }
  if (executedBy) {
    return (
      <div className='grid max-w-56 gap-1 text-xs'>
        <span>执行：{executedBy}</span>
        <span className='text-muted-foreground'>{formatDate(metadataText(item.metadata?.executed_at))}</span>
        <span className='text-muted-foreground'>
          退出码 {formatNumberValue(item.metadata?.exit_code)} / {formatNumberValue(item.metadata?.duration_ms)} ms
        </span>
      </div>
    )
  }
  return <span className='text-xs text-muted-foreground'>未执行</span>
}

function CommandApprovalExecuteDialog({
  item,
  onClose,
  requestAccessMFACode,
  canExecute,
}: {
  item: PlatformItem
  onClose: () => void
  requestAccessMFACode: RequestAccessMFACode
  canExecute: boolean
}) {
  const app = useApp()
  const [timeoutSeconds, setTimeoutSeconds] = useState('30')
  const [result, setResult] = useState<Record<string, unknown> | null>(null)
  const [running, setRunning] = useState(false)

  const execute = async () => {
    if (!canExecute) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setRunning(true)
    try {
      const run = (mfaCode = '') => apiRequest<Record<string, unknown>>(`/api/admin/command-approvals/${item.id}/execute`, {
        method: 'POST',
        body: JSON.stringify(mfaCode ? { timeout_seconds: Number(timeoutSeconds) || 30, mfa_code: mfaCode } : { timeout_seconds: Number(timeoutSeconds) || 30 }),
      })
      let data: Record<string, unknown>
      try {
        data = await run()
      } catch (error) {
        if (!isAccessMFARequiredError(error)) throw error
        const mfaCode = await requestAccessMFACode()
        if (!mfaCode) return
        data = await run(mfaCode)
      }
      setResult(data)
      await app.refresh(true)
      app.showToast('已执行批准命令')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setRunning(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={`${item.name} 执行`} description='批准后的 SSH 命令会使用原始资产和凭据上下文执行。'>
      <div className='grid gap-4'>
        <div className='rounded-lg border border-border bg-muted/20 p-3 text-xs'>
          <div className='font-medium text-foreground'>命令</div>
          <pre className='mt-2 max-h-36 overflow-auto whitespace-pre-wrap rounded-md bg-background p-2 font-mono'>{metadataText(item.metadata?.command) || '-'}</pre>
        </div>
        <Field label='超时时间（秒）'>
          <Input type='number' min={1} max={600} value={timeoutSeconds} onChange={(event) => setTimeoutSeconds(event.currentTarget.value)} />
        </Field>
        {result ? <CommandApprovalResultPanel result={result} /> : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>关闭</Button>
          <Button variant='primary' onClick={() => void execute()} disabled={running || !canExecute}>
            <Play className='size-4' />
            {running ? '执行中' : '执行'}
          </Button>
        </div>
      </div>
    </DialogShell>
  )
}

function CommandApprovalResultPanel({ result }: { result: Record<string, unknown> }) {
  const stdout = metadataText(result.stdout)
  const stderr = metadataText(result.stderr) || metadataText(result.error)
  return (
    <div className='rounded-xl border border-border bg-background/60 p-3'>
      <div className='flex items-center justify-between gap-3 text-sm'>
        <strong>{metadataText(result.command) || '命令结果'}</strong>
        <Badge tone={statusTone(metadataText(result.status))}>{metadataText(result.status) || '-'}</Badge>
      </div>
      <div className='mt-2 grid grid-cols-2 gap-2 text-xs text-muted-foreground'>
        <span>退出码：{formatNumberValue(result.exit_code)}</span>
        <span>耗时：{formatNumberValue(result.duration_ms)} ms</span>
      </div>
      {stdout ? <pre className='mt-3 max-h-56 overflow-auto rounded-lg bg-muted p-2 text-xs'>{stdout}</pre> : null}
      {stderr ? <pre className='mt-3 max-h-56 overflow-auto rounded-lg bg-destructive/10 p-2 text-xs text-destructive'>{stderr}</pre> : null}
    </div>
  )
}

function SQLExecuteDialog({
  item,
  onClose,
  requestAccessMFACode,
  canExecute = true,
  endpoint,
  workOrderEndpoint,
  initialSQL,
  successMessage,
  workOrderMessage,
  description,
}: {
  item: PlatformItem
  onClose: () => void
  requestAccessMFACode: RequestAccessMFACode
  canExecute?: boolean
  endpoint?: string
  workOrderEndpoint?: string
  initialSQL?: string
  successMessage?: string
  workOrderMessage?: string
  description?: string
}) {
  const app = useApp()
  const { t } = useTranslation()
  const [sql, setSQL] = useState(initialSQL ?? stringValue(item.metadata?.sql))
  const [reason, setReason] = useState('')
  const [result, setResult] = useState<PlatformItem | null>(null)
  const [running, setRunning] = useState(false)
  const [submittingWorkOrder, setSubmittingWorkOrder] = useState(false)

  const execute = async () => {
    if (!canExecute) {
      app.showToast(app.t('permissionDenied', 'Permission denied'))
      return
    }
    setRunning(true)
    try {
      const executeSQL = (mfaCode = '') => apiRequest<PlatformItem>(endpoint || `/api/admin/sql-work-orders/${item.id}/execute`, {
        method: 'POST',
        body: JSON.stringify(mfaCode ? { sql, mfa_code: mfaCode } : { sql }),
      })
      let data: PlatformItem
      try {
        data = await executeSQL()
      } catch (error) {
        if (!isAccessMFARequiredError(error)) throw error
        const mfaCode = await requestAccessMFACode()
        if (!mfaCode) return
        data = await executeSQL(mfaCode)
      }
      setResult(data)
      await app.refresh(true)
      app.showToast(successMessage || t('sqlDialog.executed'))
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
      const createWorkOrder = (mfaCode = '') => apiRequest<PlatformItem>(workOrderEndpoint, {
        method: 'POST',
        body: JSON.stringify(mfaCode ? { sql, reason, mfa_code: mfaCode } : { sql, reason }),
      })
      let data: PlatformItem
      try {
        data = await createWorkOrder()
      } catch (error) {
        if (!isAccessMFARequiredError(error)) throw error
        const mfaCode = await requestAccessMFACode()
        if (!mfaCode) return
        data = await createWorkOrder(mfaCode)
      }
      setResult(data)
      setReason('')
      await app.refresh(true)
      app.showToast(workOrderMessage || t('sqlDialog.workOrderSubmitted'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSubmittingWorkOrder(false)
    }
  }

  return (
    <DialogShell open onOpenChange={(open) => !open && onClose()} title={t('sqlDialog.title', { name: item.name })} description={description || t('sqlDialog.description')}>
      <div className='grid gap-4'>
        <Field label='SQL'><Textarea className='min-h-44 font-mono text-xs' value={sql} onChange={(event) => setSQL(event.currentTarget.value)} /></Field>
        {workOrderEndpoint ? (
          <Field label={t('sqlDialog.reason')}><Input value={reason} onChange={(event) => setReason(event.currentTarget.value)} placeholder={t('sqlDialog.reasonPlaceholder')} /></Field>
        ) : null}
        {result ? <SQLResultPanel result={result} /> : null}
        <div className='flex justify-end gap-2'>
          <Button variant='outline' onClick={onClose}>{t('sqlDialog.close')}</Button>
          {workOrderEndpoint ? (
            <Button variant='outline' onClick={() => void submitWorkOrder()} disabled={submittingWorkOrder || !sql.trim()}>
              <Plus className='size-4' />
              {submittingWorkOrder ? t('sqlDialog.submitting') : t('sqlDialog.submitWorkOrder')}
            </Button>
          ) : null}
          <Button variant='primary' onClick={() => void execute()} disabled={running || !canExecute || !sql.trim()}>
            <Play className='size-4' />
            {running ? t('sqlDialog.running') : t('sqlDialog.execute')}
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
  const isAssetGroup = collection === 'asset_groups'
  const isRole = collection === 'roles'
  const isCommandFilter = collection === 'command_filters'
  const isCommandSnippet = collection === 'command_snippets'
  const isAuthorizationStrategy = collection === 'authorization_strategies'
  const isOIDCClient = collection === 'oidc_clients'
  const isAsset = collection === 'assets'
  const isWebAsset = collection === 'web_assets'
  const isDatabaseAsset = collection === 'database_assets'
  const isScheduledTask = collection === 'scheduled_tasks'
  const roleItems = app.data.platform?.roles || []
  const assetGroupItems = (app.data.platform?.asset_groups || items).filter((item) => item.id !== editingId)
  const storageItems = app.data.platform?.storages || []
  const assetItems = app.data.platform?.assets || []
  const authorizationResourceType = metadataFormText(form.metadata, 'resource_type') || 'storage'
  const gatewayGroupItems = app.data.platform?.gateway_groups || []
  const databaseCredentials = (app.data.platform?.credentials || []).filter((item) => item.type === 'database_password')
  const mtlsCertificates = (app.data.platform?.certificates || []).filter((item) => metadataBool(item.metadata?.mtls_enabled) && metadataBool(item.metadata?.has_private_key))
  return (
    <DialogShell open={open} onOpenChange={onOpenChange} title={title} description={description}>
      <div className='grid gap-4'>
        <div className='grid gap-3 sm:grid-cols-2'>
          {isAssetGroup ? (
            <>
              <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('status')}>
                <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                  <option value='enabled'>{app.t('enabled', '启用')}</option>
                  <option value='disabled'>{app.t('disabled', '禁用')}</option>
                </Select>
              </Field>
              <Field label={app.t('type', '类型')}>
                <Select value={form.type || 'ssh'} onChange={(event) => onChange({ type: event.currentTarget.value })}>
                  <option value='ssh'>SSH / Text</option>
                  <option value='desktop'>RDP / VNC</option>
                  <option value='web'>Web</option>
                  <option value='database'>Database</option>
                  <option value='custom'>{app.t('custom', '自定义')}</option>
                </Select>
              </Field>
              <Field label={app.t('protocol')}>
                <Select value={form.protocol} onChange={(event) => onChange({ protocol: event.currentTarget.value })}>
                  <option value=''>{app.t('none', '无')}</option>
                  <option value='ssh'>SSH</option>
                  <option value='rdp'>RDP</option>
                  <option value='vnc'>VNC</option>
                  <option value='http'>HTTP</option>
                  <option value='database'>Database</option>
                </Select>
              </Field>
              <Field label={app.t('parent', '上级/分组')}>
                <Select value={form.parent_id} onChange={(event) => onChange({ parent_id: event.currentTarget.value })}>
                  <option value=''>{app.t('none', '无')}</option>
                  {assetGroupItems.map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
                  ))}
                </Select>
              </Field>
              <Field label={app.t('sort', '排序')}>
                <Input type='number' value={metadataFormText(form.metadata, 'sort')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'sort', event.currentTarget.value ? Number(event.currentTarget.value) : '') })} />
              </Field>
              <label className='flex items-center gap-2 rounded-lg border border-border bg-muted/20 px-3 py-2 text-sm sm:col-span-2'>
                <input
                  type='checkbox'
                  className='size-4 accent-primary'
                  checked={metadataBoolFromForm(form.metadata, 'collapsed')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'collapsed', event.currentTarget.checked) })}
                />
                <span>{app.t('collapsedByDefault', '默认折叠')}</span>
              </label>
              <Field label={app.t('tags', '标签')}><Input placeholder='prod,linux,rdp' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
            </>
          ) : isCommandFilter ? (
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
              <Field label={app.t('targetResourceType', '目标资源类型')}>
                <Select
                  value={authorizationResourceType}
                  onChange={(event) => onChange({
                    target_id: '',
                    metadata: metadataWithValue(form.metadata, 'resource_type', event.currentTarget.value),
                  })}
                >
                  <option value='storage'>{app.t('storageResource', '用户存储')}</option>
                  <option value='asset'>{app.t('assetResource', '服务器资产')}</option>
                </Select>
              </Field>
              <Field label={authorizationResourceType === 'asset' ? app.t('targetAsset', '目标资产') : app.t('targetStorage', '目标存储')}>
                <Select value={form.target_id} onChange={(event) => onChange({ target_id: event.currentTarget.value })}>
                  <option value=''>{authorizationResourceType === 'asset' ? app.t('allAssets', '全部资产') : app.t('allStorages', '全部存储')}</option>
                  {(authorizationResourceType === 'asset' ? assetItems : storageItems).map((item) => (
                    <option key={item.id} value={item.id}>{item.name}</option>
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
          ) : isWebAsset ? (
            <>
              <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('status')}>
                <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                  <option value='enabled'>{app.t('enabled', 'Enabled')}</option>
                  <option value='disabled'>{app.t('disabled', 'Disabled')}</option>
                </Select>
              </Field>
              <Field label={app.t('type', 'Type')}>
                <Select value={form.type || 'http'} onChange={(event) => onChange({ type: event.currentTarget.value, protocol: 'http' })}>
                  <option value='http'>HTTP</option>
                  <option value='https'>HTTPS</option>
                </Select>
              </Field>
              <Field label={app.t('targetUrl', 'Target URL')}>
                <Input
                  placeholder='https://internal.example.local'
                  value={metadataFormText(form.metadata, 'target_url')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'target_url', event.currentTarget.value) })}
                />
              </Field>
              {(metadataBoolFromForm(form.metadata, 'web_upstream_url_set') || metadataBoolFromForm(form.metadata, 'upstream_credentials_set')) ? (
                <div className='sm:col-span-2 grid gap-2 rounded-lg border border-border bg-muted/20 p-3'>
                  <div className='flex flex-wrap items-center justify-between gap-2'>
                    <span className='text-sm font-medium'>{app.t('upstreamCredentials', 'Upstream credentials')}</span>
                    <Badge tone='success'>{app.t('passwordSaved')}</Badge>
                  </div>
                  <CheckboxRow
                    checked={metadataBoolFromForm(form.metadata, 'web_upstream_credentials_clear')}
                    onChange={(checked) => onChange({ metadata: metadataWithWebAssetCredentialClear(form.metadata, checked) })}
                    label={app.t('clearUpstreamCredentials', 'Clear saved upstream credentials on save')}
                  />
                  <p className='text-xs text-muted-foreground'>{app.t('clearUpstreamCredentialsHint', 'The target URL can stay the same; saving removes stored upstream userinfo from the backend.')}</p>
                </div>
              ) : null}
              <Field label={app.t('hostDomain', 'Host / domain')}>
                <Input placeholder='app.example.com' value={form.host} onChange={(event) => onChange({ host: event.currentTarget.value })} />
              </Field>
              <Field label={app.t('ports')}>
                <Input type='number' placeholder={form.type === 'https' ? '443' : '80'} value={form.port} onChange={(event) => onChange({ port: event.currentTarget.value })} />
              </Field>
              <Field label={app.t('clientCertificate', 'Client certificate')}>
                <Select
                  value={metadataFormText(form.metadata, 'certificate_id') || metadataFormText(form.metadata, 'mtls_certificate_id')}
                  onChange={(event) => onChange({ metadata: metadataWithWebAssetCertificate(form.metadata, event.currentTarget.value) })}
                >
                  <option value=''>{app.t('none', 'None')}</option>
                  {mtlsCertificates.map((certificate) => (
                    <option key={certificate.id} value={certificate.id}>{certificate.name}</option>
                  ))}
                </Select>
              </Field>
              <Field label={app.t('tlsServerName', 'TLS server name')}>
                <Input
                  placeholder='internal.example.local'
                  value={metadataFormText(form.metadata, 'tls_server_name')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'tls_server_name', event.currentTarget.value) })}
                />
              </Field>
              <Field label={app.t('gatewayGroup', '网关分组')}>
                <Select value={metadataFormText(form.metadata, 'gateway_group_id')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'gateway_group_id', event.currentTarget.value) })}>
                  <option value=''>{app.t('directAccess', '直连')}</option>
                  {gatewayGroupItems.map((group) => (
                    <option key={group.id} value={group.id}>{group.name}</option>
                  ))}
                </Select>
              </Field>
              <Field className='sm:col-span-2' label={app.t('caBundle', 'CA bundle')}>
                <Textarea
                  className='min-h-36 font-mono text-xs'
                  placeholder='-----BEGIN CERTIFICATE-----'
                  value={metadataFormText(form.metadata, 'mtls_ca')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'mtls_ca', event.currentTarget.value) })}
                />
              </Field>
              <Field label={app.t('group')}><Input value={form.group} onChange={(event) => onChange({ group: event.currentTarget.value })} /></Field>
              <Field label={app.t('tags', 'Tags')}><Input placeholder='web,prod' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
              <Field className='sm:col-span-2' label={app.t('details')}>
                <Textarea value={form.description} onChange={(event) => onChange({ description: event.currentTarget.value })} />
              </Field>
            </>
          ) : isDatabaseAsset ? (
            <>
              <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('status')}>
                <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                  <option value='enabled'>{app.t('enabled', '启用')}</option>
                  <option value='disabled'>{app.t('disabled', '禁用')}</option>
                </Select>
              </Field>
              <Field label={app.t('databaseDriver', '数据库类型')}>
                <Select value={form.type || 'sqlite'} onChange={(event) => onChange({ type: event.currentTarget.value, protocol: 'database' })}>
                  <option value='sqlite'>SQLite</option>
                  <option value='mysql'>MySQL / MariaDB</option>
                  <option value='postgres'>PostgreSQL</option>
                </Select>
              </Field>
              {form.type === 'sqlite' || !form.type ? (
                <Field label={app.t('sqlitePath', 'SQLite 路径')}>
                  <Input placeholder='ops.db' value={metadataFormText(form.metadata, 'sqlite_path')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'sqlite_path', event.currentTarget.value) })} />
                </Field>
              ) : (
                <>
                  <Field label={app.t('address')}><Input placeholder='db.internal' value={form.host} onChange={(event) => onChange({ host: event.currentTarget.value })} /></Field>
                  <Field label={app.t('ports')}><Input type='number' placeholder={form.type === 'postgres' ? '5432' : '3306'} value={form.port} onChange={(event) => onChange({ port: event.currentTarget.value })} /></Field>
                  <Field label={app.t('databaseName', '数据库名')}>
                    <Input placeholder={form.type === 'postgres' ? 'postgres' : 'app'} value={metadataFormText(form.metadata, 'database')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'database', event.currentTarget.value) })} />
                  </Field>
                  <Field label={app.t('username', '用户')}><Input value={form.username} onChange={(event) => onChange({ username: event.currentTarget.value })} /></Field>
                  <Field label={app.t('credential', '凭据')}>
                    <Select value={metadataFormText(form.metadata, 'credential_id')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'credential_id', event.currentTarget.value) })}>
                      <option value=''>{app.t('none', '无')}</option>
                      {databaseCredentials.map((credential) => (
                        <option key={credential.id} value={credential.id}>{credential.name} {credential.username ? `(${credential.username})` : ''}</option>
                      ))}
                    </Select>
                  </Field>
                  {form.type === 'postgres' ? (
                    <Field label='SSL mode'>
                      <Select value={metadataFormText(form.metadata, 'sslmode') || 'disable'} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'sslmode', event.currentTarget.value) })}>
                        <option value='disable'>disable</option>
                        <option value='require'>require</option>
                        <option value='verify-ca'>verify-ca</option>
                        <option value='verify-full'>verify-full</option>
                      </Select>
                    </Field>
                  ) : (
                    <Field label='Charset'>
                      <Input placeholder='utf8mb4' value={metadataFormText(form.metadata, 'charset')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'charset', event.currentTarget.value) })} />
                    </Field>
                  )}
                </>
              )}
              <Field label={app.t('rowLimit', '行数限制')}>
                <Input type='number' placeholder='100' value={metadataFormText(form.metadata, 'row_limit')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'row_limit', event.currentTarget.value ? Number(event.currentTarget.value) : '') })} />
              </Field>
              <Field label={app.t('queryTimeoutMs', '查询超时 ms')}>
                <Input
                  type='number'
                  min={100}
                  max={600000}
                  placeholder='30000'
                  value={metadataFormText(form.metadata, 'query_timeout_ms')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'query_timeout_ms', event.currentTarget.value ? Number(event.currentTarget.value) : '') })}
                />
              </Field>
              {form.databaseDSNSet ? (
                <div className='grid gap-2 rounded-lg border border-border bg-muted/20 p-3 sm:col-span-2'>
                  <div className='flex flex-wrap items-center justify-between gap-2'>
                    <span className='text-sm font-medium'>{app.t('databaseDSN', 'Database DSN')}</span>
                    <Badge tone='success'>{app.t('passwordSaved')}</Badge>
                  </div>
                  <CheckboxRow
                    checked={form.databaseDSNClear}
                    onChange={(checked) => onChange({ databaseDSNClear: checked })}
                    label={app.t('clearDatabaseDSN', 'Clear saved database DSN on save')}
                  />
                </div>
              ) : null}
              <Field label={app.t('gatewayGroup', '网关分组')}>
                <Select value={metadataFormText(form.metadata, 'gateway_group_id')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'gateway_group_id', event.currentTarget.value) })}>
                  <option value=''>{app.t('directAccess', '直连')}</option>
                  {gatewayGroupItems.map((group) => (
                    <option key={group.id} value={group.id}>{group.name}</option>
                  ))}
                </Select>
              </Field>
              <Field label={app.t('group')}><Input value={form.group} onChange={(event) => onChange({ group: event.currentTarget.value })} /></Field>
              <Field label={app.t('tags', '标签')}><Input placeholder='mysql,prod' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
            </>
          ) : isScheduledTask ? (
            <>
              <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('status')}>
                <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                  <option value='enabled'>{app.t('enabled', 'Enabled')}</option>
                  <option value='disabled'>{app.t('disabled', 'Disabled')}</option>
                </Select>
              </Field>
              <Field label={app.t('type', 'Type')}>
                <Select value={form.type || 'asset-status'} onChange={(event) => onChange({ type: event.currentTarget.value })}>
                  <option value='asset-status'>Asset status check</option>
                  <option value='log-cleanup'>Log cleanup</option>
                  <option value='certificate-renewal'>Certificate renewal</option>
                  <option value='backup'>Backup</option>
                  <option value='custom'>Custom / record only</option>
                </Select>
              </Field>
              <Field label={app.t('intervalSeconds', 'Interval seconds')}>
                <Input
                  type='number'
                  min={1}
                  placeholder='600'
                  value={metadataFormText(form.metadata, 'interval_seconds')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'interval_seconds', event.currentTarget.value ? Number(event.currentTarget.value) : '') })}
                />
              </Field>
              <Field label={app.t('cronExpression', 'Cron expression')}>
                <Input
                  placeholder='0 0/10 * * * ?'
                  value={metadataFormText(form.metadata, 'cron')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'cron', event.currentTarget.value) })}
                />
              </Field>
              <Field label={app.t('nextRun', 'Next run')}>
                <Input
                  placeholder='2026-07-06T12:00:00Z'
                  value={metadataFormText(form.metadata, 'next_run_at')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'next_run_at', event.currentTarget.value) })}
                />
              </Field>
              <label className='flex items-center gap-2 rounded-lg border border-border bg-muted/20 px-3 py-2 text-sm sm:col-span-2'>
                <input
                  type='checkbox'
                  className='size-4 accent-primary'
                  checked={metadataBoolFromForm(form.metadata, 'run_on_start')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'run_on_start', event.currentTarget.checked) })}
                />
                <span>{app.t('runOnStart', 'Run once on scheduler start')}</span>
              </label>
              {form.type === 'asset-status' ? (
                <Field label={app.t('timeoutMs', 'Timeout ms')}>
                  <Input
                    type='number'
                    min={100}
                    max={30000}
                    placeholder='2000'
                    value={metadataFormText(form.metadata, 'timeout_ms')}
                    onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'timeout_ms', event.currentTarget.value ? Number(event.currentTarget.value) : '') })}
                  />
                </Field>
              ) : null}
              {form.type === 'log-cleanup' ? (
                <Field label={app.t('retentionDays', 'Retention days')}>
                  <Input
                    type='number'
                    min={0}
                    placeholder='90'
                    value={metadataFormText(form.metadata, 'retention_days')}
                    onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'retention_days', event.currentTarget.value ? Number(event.currentTarget.value) : '') })}
                  />
                </Field>
              ) : null}
              {form.type === 'certificate-renewal' ? (
                <>
                  <Field label={app.t('renewBeforeDays', 'Renew before days')}>
                    <Input
                      type='number'
                      min={0}
                      placeholder='30'
                      value={metadataFormText(form.metadata, 'renew_before_days')}
                      onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'renew_before_days', event.currentTarget.value ? Number(event.currentTarget.value) : '') })}
                    />
                  </Field>
                  <Field label={app.t('validityDays', 'Validity days')}>
                    <Input
                      type='number'
                      min={1}
                      placeholder='365'
                      value={metadataFormText(form.metadata, 'validity_days')}
                      onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'validity_days', event.currentTarget.value ? Number(event.currentTarget.value) : '') })}
                    />
                  </Field>
                </>
              ) : null}
              <Field label={app.t('group')}><Input value={form.group} onChange={(event) => onChange({ group: event.currentTarget.value })} /></Field>
              <Field label={app.t('tags', 'Tags')}><Input placeholder='ops,backup' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
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
          ) : isOIDCClient ? (
            <>
              <Field label={app.t('name')}><Input value={form.name} onChange={(event) => onChange({ name: event.currentTarget.value })} /></Field>
              <Field label={app.t('status')}>
                <Select value={form.status || 'enabled'} onChange={(event) => onChange({ status: event.currentTarget.value })}>
                  <option value='enabled'>{app.t('enabled', 'Enabled')}</option>
                  <option value='disabled'>{app.t('disabled', 'Disabled')}</option>
                </Select>
              </Field>
              <Field label={app.t('clientType', 'Client type')}>
                <Select
                  value={form.type || 'confidential'}
                  onChange={(event) => {
                    const nextType = event.currentTarget.value
                    onChange({
                      type: nextType,
                      password: nextType === 'public' ? '' : form.password,
                      oidcClientSecretClear: nextType === 'public' ? false : form.oidcClientSecretClear,
                      metadata: metadataWithValue(form.metadata, 'token_endpoint_auth_method', nextType === 'public' ? 'none' : 'client_secret_basic'),
                    })
                  }}
                >
                  <option value='confidential'>{app.t('confidentialClient', 'Confidential')}</option>
                  <option value='public'>{app.t('publicClient', 'Public')}</option>
                </Select>
              </Field>
              <Field label={app.t('oidcClientID', 'Client ID')}>
                <Input
                  placeholder='openweb-client'
                  value={metadataFormText(form.metadata, 'client_id')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'client_id', event.currentTarget.value) })}
                />
              </Field>
              <Field label={app.t('oidcClientSecret', 'Client secret')}>
                <Input
                  type='password'
                  value={form.password}
                  placeholder={editingId ? app.t('keepCurrentSecret', 'Leave blank to keep current secret') : ''}
                  autoComplete='new-password'
                  disabled={(form.type || 'confidential') === 'public'}
                  onChange={(event) => onChange({ password: event.currentTarget.value, oidcClientSecretClear: false })}
                />
              </Field>
              {editingId && (form.type || 'confidential') !== 'public' && form.oidcClientSecretSet ? (
                <div className='grid gap-2 rounded-lg border border-border bg-muted/20 p-3 sm:col-span-2'>
                  <div className='flex flex-wrap items-center justify-between gap-2'>
                    <span className='text-sm font-medium'>{app.t('oidcClientSecret', 'Client secret')}</span>
                    <Badge tone='success'>{app.t('passwordSaved')}</Badge>
                  </div>
                  <CheckboxRow
                    checked={form.oidcClientSecretClear}
                    onChange={(checked) => onChange({ oidcClientSecretClear: checked, password: checked ? '' : form.password })}
                    label={app.t('clearOIDCClientSecret', 'Clear saved OIDC client secret on save')}
                  />
                </div>
              ) : null}
              <Field label={app.t('oidcAuthMethod', 'Token auth method')}>
                <Select
                  value={metadataFormText(form.metadata, 'token_endpoint_auth_method') || ((form.type || 'confidential') === 'public' ? 'none' : 'client_secret_basic')}
                  onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'token_endpoint_auth_method', event.currentTarget.value) })}
                >
                  <option value='client_secret_basic'>client_secret_basic</option>
                  <option value='client_secret_post'>client_secret_post</option>
                  <option value='none'>none</option>
                </Select>
              </Field>
              <Field className='sm:col-span-2' label={app.t('oidcRedirectURIs', 'Redirect URIs')}>
                <Textarea
                  className='font-mono text-xs'
                  placeholder={'https://client.example.com/callback\nhttp://localhost:3000/callback'}
                  value={metadataFormText(form.metadata, 'redirect_uris')}
                  onChange={(event) => onChange({ metadata: metadataWithList(form.metadata, 'redirect_uris', splitLines(event.currentTarget.value)) })}
                />
              </Field>
              <Field className='sm:col-span-2' label={app.t('oidcScopes', 'Scopes')}>
                <Input
                  placeholder='openid profile email'
                  value={metadataListInputText(form.metadata, 'scopes')}
                  onChange={(event) => onChange({ metadata: metadataWithList(form.metadata, 'scopes', splitWords(event.currentTarget.value)) })}
                />
              </Field>
              <Field label={app.t('group')}><Input value={form.group} onChange={(event) => onChange({ group: event.currentTarget.value })} /></Field>
              <Field label={app.t('tags', 'Tags')}><Input placeholder='sso,internal' value={form.tags} onChange={(event) => onChange({ tags: event.currentTarget.value })} /></Field>
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
              {isAsset ? (
                <Field label={app.t('gatewayGroup', '网关分组')}>
                  <Select value={metadataFormText(form.metadata, 'gateway_group_id')} onChange={(event) => onChange({ metadata: metadataWithValue(form.metadata, 'gateway_group_id', event.currentTarget.value) })}>
                    <option value=''>{app.t('directAccess', '直连')}</option>
                    {gatewayGroupItems.map((group) => (
                      <option key={group.id} value={group.id}>{group.name}</option>
                    ))}
                  </Select>
                </Field>
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
  if (collection === 'asset_groups') return 'ssh'
  if (collection === 'roles') return 'custom'
  if (collection === 'command_filters') return 'deny'
  if (collection === 'command_snippets') return 'public'
  if (collection === 'authorization_strategies') return 'file'
  if (collection === 'oidc_clients') return 'confidential'
  if (collection === 'web_assets') return 'http'
  if (collection === 'database_assets') return 'sqlite'
  if (collection === 'scheduled_tasks') return 'asset-status'
  return ''
}

function defaultPlatformPermissions(collection: string): Record<string, boolean> {
  if (collection !== 'authorization_strategies') return {}
  return { upload: true, download: true, edit: true, delete: false, rename: true, copy: true, paste: true }
}

function defaultPlatformMetadata(collection: string) {
  if (collection === 'command_filters') return JSON.stringify({ risk: 'high' }, null, 2)
  if (collection === 'asset_groups') return JSON.stringify({ sort: 0, collapsed: false }, null, 2)
  if (collection === 'command_snippets') return JSON.stringify({ command: '', append_newline: false }, null, 2)
  if (collection === 'authorization_strategies') return JSON.stringify({ resource_type: 'storage', path_prefix: '' }, null, 2)
  if (collection === 'oidc_clients') return JSON.stringify({
    client_id: '',
    redirect_uris: [],
    scopes: ['openid', 'profile', 'email'],
    token_endpoint_auth_method: 'client_secret_basic',
  }, null, 2)
  if (collection === 'web_assets') return JSON.stringify({ target_url: '' }, null, 2)
  if (collection === 'database_assets') return JSON.stringify({ sqlite_path: '', row_limit: 100, query_timeout_ms: 30000 }, null, 2)
  if (collection === 'scheduled_tasks') return JSON.stringify({ interval_seconds: 600, timeout_ms: 2000 }, null, 2)
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
    oidcClientSecretSet: metadataBool(item.metadata?.client_secret_set),
    oidcClientSecretClear: false,
    databaseDSNSet: metadataBool(item.metadata?.database_dsn_set),
    databaseDSNClear: false,
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
  if (form.oidcClientSecretClear) {
    metadata = { ...(metadata ?? {}), client_secret_clear: true }
  }
  if (form.databaseDSNClear) {
    metadata = { ...(metadata ?? {}), database_dsn_clear: true }
  }
  return {
    name: form.name,
    type: form.type,
    status: form.status,
    protocol: form.protocol || undefined,
    host: form.host,
    port: form.port ? Number(form.port) : 0,
    username: form.username,
    password: form.oidcClientSecretClear ? undefined : form.password || undefined,
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

function CheckboxRow({ checked, onChange, label }: { checked: boolean; onChange: (checked: boolean) => void; label: string }) {
  return (
    <label className='flex min-h-9 items-center gap-2 rounded-lg border border-border bg-muted/20 px-3 py-2 text-sm'>
      <input
        type='checkbox'
        className='size-4 accent-primary'
        checked={checked}
        onChange={(event) => onChange(event.currentTarget.checked)}
      />
      <span>{label}</span>
    </label>
  )
}

export function PlatformSettingsPage({ config, sectionId }: { config: PlatformPageConfig; sectionId?: string }) {
  const app = useApp()
  const items = app.data.platform?.[config.collection] || []
  const label = platformLabel(config, app.locale)
  const description = platformDescription(config, app.locale)
  const Icon = config.icon
  const brandingSetting = useMemo(() => items.find((item) => (item.type || '').toLowerCase() === 'branding'), [items])
  const accessSetting = useMemo(() => items.find((item) => (item.type || '').toLowerCase() === 'access'), [items])
  const integration = useMemo(() => items.find((item) => (item.type || '').toLowerCase() === 'integration'), [items])
  const proxySetting = useMemo(() => items.find((item) => (item.type || '').toLowerCase() === 'proxy'), [items])
  const [brandingForm, setBrandingForm] = useState<BrandingForm>(() => brandingFormFromItem(brandingSetting, app.publicConfig))
  const [accessForm, setAccessForm] = useState<DesktopAccessForm>(() => desktopAccessFormFromItem(accessSetting))
  const [form, setForm] = useState<SMTPIntegrationForm>(() => smtpIntegrationFormFromItem(integration))
  const [proxyForm, setProxyForm] = useState<ProxyServicesForm>(() => proxyServicesFormFromItem(proxySetting))
  const [proxyStatus, setProxyStatus] = useState<ProxyServicesStatus>({})
  const [savingBranding, setSavingBranding] = useState(false)
  const [savingAccess, setSavingAccess] = useState(false)
  const [savingProxy, setSavingProxy] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testingLLM, setTestingLLM] = useState(false)
  const role = app.auth?.role
  const apiPermissions = app.auth?.api_permissions || []
  const canUsePath: CanUsePath = (method, path) => canUseAPI(role, apiPermissions, method, path)
  const canReadProxyServices = canUsePath('GET', '/api/admin/proxy-services')
  const canSaveProxyServicesConfig = canUsePath('POST', '/api/admin/proxy-services')
  const canCreateSystemSettings = canUsePath('POST', '/api/admin/system-settings')
  const canSaveSystemSetting = (id?: string) => id ? canUsePath('PATCH', `/api/admin/system-settings/${id}`) : canCreateSystemSettings
  const canSaveBrandingSettings = canSaveSystemSetting(brandingSetting?.id)
  const canSaveAccessSettings = canSaveSystemSetting(accessSetting?.id)
  const canSaveIntegrationSettings = canSaveSystemSetting(integration?.id)
  const canTestSMTPSettings = canUsePath('POST', '/api/admin/system-settings/smtp/test')
  const canTestLLMSettings = canUsePath('POST', '/api/admin/system-settings/llm/test')
  const canRunSMTPTest = canTestSMTPSettings && (canSaveIntegrationSettings || Boolean(integration?.id))
  const canRunLLMTest = canTestLLMSettings && (canSaveIntegrationSettings || Boolean(integration?.id))
  const showPermissionDenied = () => app.showToast(app.t('permissionDenied', 'Permission denied'))

  useEffect(() => {
    setBrandingForm(brandingFormFromItem(brandingSetting, app.publicConfig))
  }, [brandingSetting?.id, brandingSetting?.updated_at, app.publicConfig.site_name, app.publicConfig.logo_url])

  useEffect(() => {
    setAccessForm(desktopAccessFormFromItem(accessSetting))
  }, [accessSetting?.id, accessSetting?.updated_at])

  useEffect(() => {
    setForm(smtpIntegrationFormFromItem(integration))
  }, [integration?.id, integration?.updated_at])

  useEffect(() => {
    setProxyForm(proxyServicesFormFromItem(proxySetting))
  }, [proxySetting?.id, proxySetting?.updated_at])

  useEffect(() => {
    if (!canReadProxyServices) {
      setProxyStatus({})
      return
    }
    let alive = true
    const load = async () => {
      try {
        const data = await apiRequest<{ status?: ProxyServicesStatus; settings?: PlatformItem }>('/api/admin/proxy-services')
        if (!alive) return
        setProxyStatus(data.status || {})
        if (data.settings) setProxyForm(proxyServicesFormFromItem(data.settings))
      } catch {
        if (alive) setProxyStatus({})
      }
    }
    void load()
    return () => {
      alive = false
    }
  }, [canReadProxyServices])

  const patchAccessForm = (next: Partial<DesktopAccessForm>) => setAccessForm((current) => ({ ...current, ...next }))
  const patchBrandingForm = (next: Partial<BrandingForm>) => setBrandingForm((current) => ({ ...current, ...next }))
  const patchForm = (next: Partial<SMTPIntegrationForm>) => setForm((current) => ({ ...current, ...next }))
  const patchProxyForm = (next: Partial<ProxyServicesForm>) => setProxyForm((current) => ({ ...current, ...next }))

  const saveBrandingSettings = async () => {
    if (!canSaveBrandingSettings) {
      showPermissionDenied()
      return
    }
    setSavingBranding(true)
    try {
      await apiRequest<PlatformItem>(brandingSetting?.id ? `/api/admin/system-settings/${brandingSetting.id}` : '/api/admin/system-settings', {
        method: brandingSetting?.id ? 'PATCH' : 'POST',
        body: JSON.stringify({
          name: brandingSetting?.name || 'System branding',
          type: 'branding',
          status: 'enabled',
          metadata: brandingMetadataFromForm(brandingForm, brandingSetting?.metadata),
          description: 'Public branding, logo, ICP record, footer, navigation, and about page content.',
        }),
      })
      await app.refresh(true)
      app.showToast(app.t('saved', 'Saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSavingBranding(false)
    }
  }

  const saveAccessSettings = async () => {
    if (!canSaveAccessSettings) {
      showPermissionDenied()
      return
    }
    setSavingAccess(true)
    try {
      await apiRequest<PlatformItem>(accessSetting?.id ? `/api/admin/system-settings/${accessSetting.id}` : '/api/admin/system-settings', {
        method: accessSetting?.id ? 'PATCH' : 'POST',
        body: JSON.stringify({
          name: accessSetting?.name || 'Asset access settings',
          type: 'access',
          status: 'enabled',
          metadata: desktopAccessMetadataFromForm(accessForm, accessSetting?.metadata),
          description: 'Desktop access defaults for RDP/VNC sessions, recording, clipboard, file transfer, and watermark.',
        }),
      })
      await app.refresh(true)
      app.showToast(app.t('saved', 'Saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSavingAccess(false)
    }
  }

  const saveIntegration = async (silent = false) => {
    if (!canSaveIntegrationSettings) {
      if (!silent) showPermissionDenied()
      return null
    }
    setSaving(true)
    try {
      const saved = await apiRequest<PlatformItem>(integration?.id ? `/api/admin/system-settings/${integration.id}` : '/api/admin/system-settings', {
        method: integration?.id ? 'PATCH' : 'POST',
        body: JSON.stringify({
          name: integration?.name || 'Notification integrations',
          type: 'integration',
          status: 'enabled',
          host: form.host.trim(),
          port: form.port ? Number(form.port) : 0,
          username: form.username.trim(),
          password: form.password.trim() || undefined,
          metadata: integrationMetadataFromForm(form, integration?.metadata),
          description: 'SMTP email delivery and LLM integration settings.',
        }),
      })
      patchForm({
        password: '',
        passwordSet: Boolean(saved.metadata?.smtp_password_set),
        passwordClear: false,
        llmApiKey: '',
        llmApiKeySet: Boolean(saved.metadata?.llm_api_key_set),
        llmApiKeyClear: false,
      })
      await app.refresh(true)
      if (!silent) app.showToast(app.t('saved', 'Saved'))
      return saved
    } catch (error) {
      app.handleApiError(error)
      return null
    } finally {
      setSaving(false)
    }
  }

  const testSMTP = async () => {
    if (!canTestSMTPSettings) {
      showPermissionDenied()
      return
    }
    setTesting(true)
    try {
      const saved = canSaveIntegrationSettings ? await saveIntegration(true) : integration
      if (!saved) return
      const result = await apiRequest<{ message?: string }>('/api/admin/system-settings/smtp/test', {
        method: 'POST',
        body: JSON.stringify({
          setting_id: saved.id,
          to: form.testTo.trim() || form.to.trim(),
          subject: 'Open Web Server Manager SMTP test',
          body: 'SMTP delivery settings are working.',
        }),
      })
      app.showToast(result.message || 'SMTP test email sent')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setTesting(false)
    }
  }

  const testLLM = async () => {
    if (!canTestLLMSettings) {
      showPermissionDenied()
      return
    }
    setTestingLLM(true)
    try {
      const saved = canSaveIntegrationSettings ? await saveIntegration(true) : integration
      if (!saved) return
      const result = await apiRequest<{ message?: string; response?: string }>('/api/admin/system-settings/llm/test', {
        method: 'POST',
        body: JSON.stringify({
          setting_id: saved.id,
          prompt: 'Reply with the single word: ok',
        }),
      })
      const suffix = result.response ? `: ${result.response.slice(0, 120)}` : ''
      app.showToast((result.message || app.t('llmTestCompleted', 'LLM test prompt completed')) + suffix)
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setTestingLLM(false)
    }
  }

  const saveProxyServices = async () => {
    if (!canSaveProxyServicesConfig) {
      showPermissionDenied()
      return
    }
    setSavingProxy(true)
    try {
      const result = await apiRequest<{ status?: ProxyServicesStatus; settings?: PlatformItem }>('/api/admin/proxy-services', {
        method: 'POST',
        body: JSON.stringify(proxyServicesPayloadFromForm(proxyForm)),
      })
      if (result.status) setProxyStatus(result.status)
      if (result.settings) {
        setProxyForm(proxyServicesFormFromItem(result.settings))
      } else {
        patchProxyForm({ proxyPrivateKey: '', proxyPrivateKeyClear: false })
      }
      await app.refresh(true)
      app.showToast(app.t('saved', 'Saved'))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setSavingProxy(false)
    }
  }
  return (
    <CardStaggerContainer>
      <CardStaggerItem id={sectionId} className='scroll-mt-20'>
        <Card>
          <CardHeader className='gap-3 max-sm:grid-cols-1'>
            <div>
              <CardTitle className='flex items-center gap-2'><Icon className='size-5 text-primary' />{label}</CardTitle>
              <CardDescription>{description}</CardDescription>
            </div>
            <Button variant='outline' onClick={() => void app.refresh()}><RefreshCw className='size-4' />{app.t('refresh', '刷新')}</Button>
          </CardHeader>
          <CardContent className='grid gap-5'>
            <section className='grid gap-4 rounded-xl border border-border bg-background/60 p-4'>
              <div className='flex flex-wrap items-start justify-between gap-3'>
                <div>
                  <h3 className='text-sm font-semibold'>{app.t('brandingSettings', 'Branding and about')}</h3>
                  <p className='mt-1 text-xs leading-5 text-muted-foreground'>
                    {app.t('brandingSettingsDescription', 'Configure the public product name, logo URLs, footer, ICP record, navigation links, and about page copy. These settings are served by /api/public/config.')}
                  </p>
                </div>
                <Badge tone={brandingSetting ? 'success' : 'neutral'}>{brandingSetting ? app.t('configured', 'Configured') : app.t('notConfigured', 'Not configured')}</Badge>
              </div>
              <div className='grid gap-3 md:grid-cols-2 xl:grid-cols-4'>
                <Field label={app.t('systemName', 'System name')}>
                  <Input value={brandingForm.siteName} onChange={(event) => patchBrandingForm({ siteName: event.currentTarget.value })} placeholder='Open Web Server Manager' />
                </Field>
                <Field label={app.t('logoUrl', 'Logo URL')}>
                  <Input value={brandingForm.logoUrl} onChange={(event) => patchBrandingForm({ logoUrl: event.currentTarget.value })} placeholder='/logo.svg or https://example.com/logo.png' />
                </Field>
                <Field label={app.t('assetLogoUrl', 'Asset logo URL')}>
                  <Input value={brandingForm.assetLogoUrl} onChange={(event) => patchBrandingForm({ assetLogoUrl: event.currentTarget.value })} placeholder='/logo.svg' />
                </Field>
                <Field label={app.t('icpNumber', 'ICP record')}>
                  <Input value={brandingForm.icpNumber} onChange={(event) => patchBrandingForm({ icpNumber: event.currentTarget.value })} placeholder='京ICP备00000000号-1' />
                </Field>
                <Field label={app.t('github', 'GitHub')}>
                  <Input value={brandingForm.githubUrl} onChange={(event) => patchBrandingForm({ githubUrl: event.currentTarget.value })} placeholder='https://github.com/weige2008/openwebservermanager' />
                </Field>
                <Field className='xl:col-span-3' label={app.t('copyright', 'Copyright')}>
                  <Input value={brandingForm.copyright} onChange={(event) => patchBrandingForm({ copyright: event.currentTarget.value })} placeholder='Copyright (c) 2026 ...' />
                </Field>
                <Field className='md:col-span-2' label={app.t('aboutTitle', 'About title')}>
                  <Input value={brandingForm.aboutTitle} onChange={(event) => patchBrandingForm({ aboutTitle: event.currentTarget.value })} placeholder='About Open Web Server Manager' />
                </Field>
                <Field className='md:col-span-2' label={app.t('aboutDescription', 'About description')}>
                  <Input value={brandingForm.aboutDescription} onChange={(event) => patchBrandingForm({ aboutDescription: event.currentTarget.value })} placeholder='Self-hosted browser workspace for server access.' />
                </Field>
              </div>
              <div className='grid gap-3 lg:grid-cols-2'>
                <Field label={app.t('aboutBody', 'About body')}>
                  <Textarea className='min-h-36' value={brandingForm.aboutBody} onChange={(event) => patchBrandingForm({ aboutBody: event.currentTarget.value })} placeholder='Public about page body text.' />
                </Field>
                <div className='grid gap-3'>
                  <Field label={app.t('footerText', 'Footer text')}>
                    <Textarea className='min-h-20' value={brandingForm.footerText} onChange={(event) => patchBrandingForm({ footerText: event.currentTarget.value })} placeholder='Footer summary shown on the homepage.' />
                  </Field>
                  <Field label={app.t('navLinks', 'Navigation links JSON')}>
                    <Textarea className='min-h-28 font-mono text-xs' value={brandingForm.navLinks} onChange={(event) => patchBrandingForm({ navLinks: event.currentTarget.value })} placeholder='[{"title":"product","href":"/#product"}]' />
                  </Field>
                </div>
              </div>
              {canSaveBrandingSettings ? (
                <div className='flex justify-end'>
                  <Button variant='outline' onClick={() => void saveBrandingSettings()} disabled={savingBranding || !brandingForm.siteName.trim()}>
                    <Save className='size-4' />
                    {savingBranding ? app.t('saving', 'Saving') : app.t('save', 'Save')}
                  </Button>
                </div>
              ) : null}
            </section>

            <section className='grid gap-4 rounded-xl border border-border bg-background/60 p-4'>
              <div className='flex flex-wrap items-start justify-between gap-3'>
                <div>
                  <h3 className='text-sm font-semibold'>{app.t('desktopAccessSettings', 'RDP/VNC access')}</h3>
                  <p className='mt-1 text-xs leading-5 text-muted-foreground'>
                    {app.t('desktopAccessSettingsDescription', 'Set default desktop resolution, clipboard, file transfer, recording, read-only mode, and workspace watermark for new RDP/VNC sessions.')}
                  </p>
                </div>
                <Badge tone={accessSetting ? 'success' : 'neutral'}>{accessSetting ? app.t('configured', 'Configured') : app.t('notConfigured', 'Not configured')}</Badge>
              </div>
              <div className='grid gap-3 md:grid-cols-2 xl:grid-cols-4'>
                <Field label={app.t('desktopWidth', 'Width')}>
                  <Input type='number' min={640} max={7680} value={accessForm.width} onChange={(event) => patchAccessForm({ width: event.currentTarget.value })} />
                </Field>
                <Field label={app.t('desktopHeight', 'Height')}>
                  <Input type='number' min={480} max={4320} value={accessForm.height} onChange={(event) => patchAccessForm({ height: event.currentTarget.value })} />
                </Field>
                <Field label='DPI'>
                  <Input type='number' min={72} max={240} value={accessForm.dpi} onChange={(event) => patchAccessForm({ dpi: event.currentTarget.value })} />
                </Field>
                <Field label={app.t('colorDepth', 'Color depth')}>
                  <Select value={accessForm.colorDepth} onChange={(event) => patchAccessForm({ colorDepth: event.currentTarget.value })}>
                    <option value='16'>16 bit</option>
                    <option value='24'>24 bit</option>
                    <option value='32'>32 bit</option>
                  </Select>
                </Field>
                <Field label={app.t('resizeMethod', 'Resize method')}>
                  <Select value={accessForm.resizeMethod} onChange={(event) => patchAccessForm({ resizeMethod: event.currentTarget.value })}>
                    <option value='display-update'>display-update</option>
                    <option value='reconnect'>reconnect</option>
                    <option value='none'>{app.t('none', 'None')}</option>
                  </Select>
                </Field>
                <Field label={app.t('accessMFAValidMinutes', 'Access MFA valid minutes')}>
                  <Input type='number' min={1} max={1440} value={accessForm.accessMfaValidMinutes} onChange={(event) => patchAccessForm({ accessMfaValidMinutes: event.currentTarget.value })} />
                </Field>
                <Field label={app.t('watermarkText', 'Watermark text')}>
                  <Input value={accessForm.watermarkText} onChange={(event) => patchAccessForm({ watermarkText: event.currentTarget.value })} placeholder='{{user}} / {{asset}}' />
                </Field>
                <Field label={app.t('watermarkColor', 'Watermark color')}>
                  <Input value={accessForm.watermarkColor} onChange={(event) => patchAccessForm({ watermarkColor: event.currentTarget.value })} placeholder='rgba(255,255,255,0.18)' />
                </Field>
                <Field label={app.t('watermarkFontSize', 'Watermark size')}>
                  <Input type='number' min={10} max={96} value={accessForm.watermarkFontSize} onChange={(event) => patchAccessForm({ watermarkFontSize: event.currentTarget.value })} />
                </Field>
              </div>
              <div className='grid gap-2 sm:grid-cols-2 xl:grid-cols-4'>
                <CheckboxRow checked={accessForm.recordingEnabled} onChange={(recordingEnabled) => patchAccessForm({ recordingEnabled })} label={app.t('defaultRecording', 'Record desktop sessions by default')} />
                <CheckboxRow checked={accessForm.clipboardEnabled} onChange={(clipboardEnabled) => patchAccessForm({ clipboardEnabled })} label={app.t('clipboardEnabled', 'Enable clipboard')} />
                <CheckboxRow checked={accessForm.fileTransferEnabled} onChange={(fileTransferEnabled) => patchAccessForm({ fileTransferEnabled })} label={app.t('fileTransferEnabled', 'Enable file transfer')} />
                <CheckboxRow checked={accessForm.sshFileTransferEnabled} onChange={(sshFileTransferEnabled) => patchAccessForm({ sshFileTransferEnabled })} label={app.t('sshFileTransferEnabled', 'Enable SSH file transfer')} />
                <CheckboxRow checked={accessForm.ignoreCert} onChange={(ignoreCert) => patchAccessForm({ ignoreCert })} label={app.t('ignoreCertificate', 'Ignore server certificate')} />
                <CheckboxRow checked={accessForm.readOnly} onChange={(readOnly) => patchAccessForm({ readOnly })} label={app.t('readOnlyDesktop', 'Read-only desktop')} />
                <CheckboxRow checked={accessForm.watermarkEnabled} onChange={(watermarkEnabled) => patchAccessForm({ watermarkEnabled })} label={app.t('workspaceWatermark', 'Workspace watermark')} />
                <CheckboxRow checked={accessForm.accessMfaEnabled} onChange={(accessMfaEnabled) => patchAccessForm({ accessMfaEnabled })} label={app.t('accessMFA', 'Require MFA before asset access')} />
              </div>
              {canSaveAccessSettings ? (
                <div className='flex justify-end'>
                  <Button variant='outline' onClick={() => void saveAccessSettings()} disabled={savingAccess}>
                    <Save className='size-4' />
                    {savingAccess ? app.t('saving', 'Saving') : app.t('save', 'Save')}
                  </Button>
                </div>
              ) : null}
            </section>

            {(canReadProxyServices || canSaveProxyServicesConfig) ? (
            <section className='grid gap-4 rounded-xl border border-border bg-background/60 p-4'>
              <div className='flex flex-wrap items-start justify-between gap-3'>
                <div>
                  <h3 className='text-sm font-semibold'>{app.t('proxyServices', 'Proxy services')}</h3>
                  <p className='mt-1 text-xs leading-5 text-muted-foreground'>
                    {app.t('proxyServicesDescription', 'Configure native SSH gateway, RDP gateway, and database proxy listener settings. SSH gateway changes are applied on the next service restart.')}
                  </p>
                </div>
                <div className='flex flex-wrap gap-2'>
                  <Badge tone={proxyStateTone(proxyStatus.ssh_gateway)}>{app.t('sshGateway', 'SSH gateway')}: {metadataText(proxyStatus.ssh_gateway?.state) || '-'}</Badge>
                  <Badge tone={proxyStateTone(proxyStatus.rdp_proxy)}>{app.t('rdpProxy', 'RDP proxy')}: {metadataText(proxyStatus.rdp_proxy?.state) || '-'}</Badge>
                  <Badge tone={proxyStateTone(proxyStatus.database_proxy)}>{app.t('databaseProxy', 'Database proxy')}: {metadataText(proxyStatus.database_proxy?.state) || '-'}</Badge>
                </div>
              </div>
              <div className='grid gap-3 lg:grid-cols-3'>
                <div className='grid gap-3 rounded-lg border border-border bg-muted/20 p-3'>
                  <CheckboxRow checked={proxyForm.sshEnabled} onChange={(sshEnabled) => patchProxyForm({ sshEnabled })} label={app.t('enableSshGateway', 'Enable SSH gateway')} />
                  <Field label={app.t('listenAddress', 'Listen address')}>
                    <Input value={proxyForm.sshListenAddress} onChange={(event) => patchProxyForm({ sshListenAddress: event.currentTarget.value })} placeholder='0.0.0.0:2022' />
                  </Field>
                  <CheckboxRow checked={proxyForm.sshDisablePasswordAuth} onChange={(sshDisablePasswordAuth) => patchProxyForm({ sshDisablePasswordAuth })} label={app.t('disablePasswordAuth', 'Disable password authentication')} />
                  <Field label={app.t('forwardAllowlist', 'Forward allowlist')}>
                    <Textarea className='min-h-24 font-mono text-xs' value={proxyForm.sshForwardAllowlist} onChange={(event) => patchProxyForm({ sshForwardAllowlist: event.currentTarget.value })} placeholder={'host:22\n10.0.0.5:5432'} />
                  </Field>
                </div>
                <div className='grid gap-3 rounded-lg border border-border bg-muted/20 p-3'>
                  <CheckboxRow checked={proxyForm.rdpEnabled} onChange={(rdpEnabled) => patchProxyForm({ rdpEnabled })} label={app.t('enableRdpProxy', 'Enable RDP proxy')} />
                  <Field label={app.t('listenAddress', 'Listen address')}>
                    <Input value={proxyForm.rdpListenAddress} onChange={(event) => patchProxyForm({ rdpListenAddress: event.currentTarget.value })} placeholder='0.0.0.0:23389' />
                  </Field>
                  <Field label={app.t('forwardAllowlist', 'Forward allowlist')}>
                    <Textarea className='min-h-24 font-mono text-xs' value={proxyForm.rdpForwardAllowlist} onChange={(event) => patchProxyForm({ rdpForwardAllowlist: event.currentTarget.value })} placeholder={'windows.internal:3389\n10.0.0.20:3389'} />
                  </Field>
                  <p className='text-xs leading-5 text-muted-foreground'>{app.t('sequentialProxyRoutesDescription', 'Targets are mapped in order to the base port, base port + 1, and subsequent ports.')}</p>
                  <div className='rounded-lg border border-border bg-background/60 p-3 text-xs text-muted-foreground'>
                    <div>{app.t('guacdAddress', 'guacd address')}: {metadataText(proxyStatus.rdp_proxy?.guacd_address) || '-'}</div>
                    <div>{app.t('state', 'State')}: {metadataText(proxyStatus.rdp_proxy?.state) || '-'}</div>
                    <div>{app.t('listenAddress', 'Listen address')}: {metadataText(proxyStatus.rdp_proxy?.listen_address) || '-'}</div>
                    <div>{app.t('liveAddress', 'Live address')}: {metadataText(proxyStatus.rdp_proxy?.live_address) || '-'}</div>
                    <div>{app.t('target', 'Target')}: {metadataText(proxyStatus.rdp_proxy?.target) || '-'}</div>
                    <div>{app.t('activeConnections', 'Active connections')}: {metadataText(proxyStatus.rdp_proxy?.active) || '0'}</div>
                    <div>{app.t('forwardAllowlist', 'Forward allowlist')}: {metadataText(proxyStatus.rdp_proxy?.allowlist_count) || '0'}</div>
                    <ProxyRouteList routes={proxyRoutes(proxyStatus.rdp_proxy?.routes)} />
                    {metadataText(proxyStatus.rdp_proxy?.last_error) ? <div className='text-destructive'>{metadataText(proxyStatus.rdp_proxy?.last_error)}</div> : null}
                  </div>
                </div>
                <div className='grid gap-3 rounded-lg border border-border bg-muted/20 p-3'>
                  <CheckboxRow checked={proxyForm.databaseEnabled} onChange={(databaseEnabled) => patchProxyForm({ databaseEnabled })} label={app.t('enableDatabaseProxy', 'Enable database proxy')} />
                  <Field label={app.t('listenAddress', 'Listen address')}>
                    <Input value={proxyForm.databaseListenAddress} onChange={(event) => patchProxyForm({ databaseListenAddress: event.currentTarget.value })} placeholder='127.0.0.1:23306' />
                  </Field>
                  <Field label={app.t('forwardAllowlist', 'Forward allowlist')}>
                    <Textarea className='min-h-24 font-mono text-xs' value={proxyForm.databaseForwardAllowlist} onChange={(event) => patchProxyForm({ databaseForwardAllowlist: event.currentTarget.value })} placeholder={'db.internal:3306\n10.0.0.10:5432'} />
                  </Field>
                  <p className='text-xs leading-5 text-muted-foreground'>{app.t('sequentialProxyRoutesDescription', 'Targets are mapped in order to the base port, base port + 1, and subsequent ports.')}</p>
                  <div className='rounded-lg border border-border bg-background/60 p-3 text-xs text-muted-foreground'>
                    <div>{app.t('state', 'State')}: {metadataText(proxyStatus.database_proxy?.state) || '-'}</div>
                    <div>{app.t('listenAddress', 'Listen address')}: {metadataText(proxyStatus.database_proxy?.listen_address) || '-'}</div>
                    <div>{app.t('liveAddress', 'Live address')}: {metadataText(proxyStatus.database_proxy?.live_address) || '-'}</div>
                    <div>{app.t('target', 'Target')}: {metadataText(proxyStatus.database_proxy?.target) || '-'}</div>
                    <div>{app.t('activeConnections', 'Active connections')}: {metadataText(proxyStatus.database_proxy?.active) || '0'}</div>
                    <div>{app.t('forwardAllowlist', 'Forward allowlist')}: {metadataText(proxyStatus.database_proxy?.allowlist_count) || '0'}</div>
                    <ProxyRouteList routes={proxyRoutes(proxyStatus.database_proxy?.routes)} />
                    {metadataText(proxyStatus.database_proxy?.last_error) ? <div className='text-destructive'>{metadataText(proxyStatus.database_proxy?.last_error)}</div> : null}
                  </div>
                </div>
              </div>
              <div className='grid gap-3 md:grid-cols-[1fr_auto] md:items-end'>
                <Field label={app.t('proxyPrivateKey', 'Proxy private key')}>
                  <Textarea className='min-h-28 font-mono text-xs' value={proxyForm.proxyPrivateKey} onChange={(event) => patchProxyForm({ proxyPrivateKey: event.currentTarget.value, proxyPrivateKeyClear: false })} placeholder={proxyForm.proxyPrivateKeySet ? app.t('leaveBlankToKeepSecret', 'Leave blank to keep current secret') : '-----BEGIN OPENSSH PRIVATE KEY-----'} autoComplete='off' />
                </Field>
                <Badge tone={proxyForm.proxyPrivateKeySet ? 'success' : 'neutral'}>{proxyForm.proxyPrivateKeySet ? app.t('privateKeySaved', 'Private key saved') : app.t('notConfigured', 'Not configured')}</Badge>
              </div>
              {proxyForm.proxyPrivateKeySet ? (
                <CheckboxRow
                  checked={proxyForm.proxyPrivateKeyClear}
                  onChange={(proxyPrivateKeyClear) => patchProxyForm({ proxyPrivateKeyClear, proxyPrivateKey: proxyPrivateKeyClear ? '' : proxyForm.proxyPrivateKey })}
                  label={app.t('clearProxyPrivateKey', 'Clear saved proxy private key on save')}
                />
              ) : null}
              {canSaveProxyServicesConfig ? (
                <div className='flex justify-end'>
                  <Button variant='outline' onClick={() => void saveProxyServices()} disabled={savingProxy}>
                    <Save className='size-4' />
                    {savingProxy ? app.t('saving', 'Saving') : app.t('save', 'Save')}
                  </Button>
                </div>
              ) : null}
            </section>
            ) : null}

            <section className='grid gap-4 rounded-xl border border-border bg-background/60 p-4'>
              <div className='flex flex-wrap items-start justify-between gap-3'>
                <div>
                  <h3 className='text-sm font-semibold'>{app.t('smtpDelivery', 'SMTP delivery')}</h3>
                  <p className='mt-1 text-xs leading-5 text-muted-foreground'>
                    {app.t('smtpDeliveryDescription', 'Configure SMTP test delivery and automatic email alerts. New security, task, gateway, and operation failures are deduplicated before delivery.')}
                  </p>
                </div>
                <Badge tone={form.passwordSet ? 'success' : 'warning'}>{form.passwordSet ? app.t('passwordSaved', 'Password saved') : app.t('passwordNotSet', 'Password not set')}</Badge>
              </div>
              <div className='grid gap-3 md:grid-cols-2 xl:grid-cols-4'>
                <Field label={app.t('smtpHost', 'SMTP host')}>
                  <Input value={form.host} onChange={(event) => patchForm({ host: event.currentTarget.value })} placeholder='smtp.example.com' />
                </Field>
                <Field label={app.t('smtpPort', 'SMTP port')}>
                  <Input type='number' value={form.port} onChange={(event) => patchForm({ port: event.currentTarget.value })} placeholder='587' />
                </Field>
                <Field label={app.t('smtpSecurity', 'Security')}>
                  <Select value={form.security} onChange={(event) => patchForm({ security: event.currentTarget.value as SMTPIntegrationForm['security'] })}>
                    <option value='starttls'>STARTTLS</option>
                    <option value='tls'>TLS</option>
                    <option value='none'>{app.t('none', 'None')}</option>
                  </Select>
                </Field>
                <Field label={app.t('smtpServerName', 'TLS server name')}>
                  <Input value={form.serverName} onChange={(event) => patchForm({ serverName: event.currentTarget.value })} placeholder={form.host || 'smtp.example.com'} />
                </Field>
                <Field label={app.t('username', 'Username')}>
                  <Input value={form.username} onChange={(event) => patchForm({ username: event.currentTarget.value })} autoComplete='username' />
                </Field>
                <Field label={app.t('password', 'Password')}>
                  <Input type='password' value={form.password} onChange={(event) => patchForm({ password: event.currentTarget.value, passwordClear: false })} placeholder={form.passwordSet ? app.t('leaveBlankToKeepSecret', 'Leave blank to keep current secret') : ''} autoComplete='new-password' />
                </Field>
                <Field label={app.t('smtpFrom', 'Sender')}>
                  <Input value={form.from} onChange={(event) => patchForm({ from: event.currentTarget.value })} placeholder='ops@example.com' />
                </Field>
                <Field label={app.t('smtpTo', 'Default recipients')}>
                  <Input value={form.to} onChange={(event) => patchForm({ to: event.currentTarget.value })} placeholder='admin@example.com, audit@example.com' />
                </Field>
                <Field className='md:col-span-2' label={app.t('smtpTestTo', 'Test recipient')}>
                  <Input value={form.testTo} onChange={(event) => patchForm({ testTo: event.currentTarget.value })} placeholder={form.to || form.from || 'admin@example.com'} />
                </Field>
                <label className='flex items-center gap-2 rounded-lg border border-border bg-muted/20 px-3 py-2 text-sm md:col-span-2'>
                  <input
                    type='checkbox'
                    className='size-4 accent-primary'
                    checked={form.insecureSkipVerify}
                    onChange={(event) => patchForm({ insecureSkipVerify: event.currentTarget.checked })}
                  />
                  <span>{app.t('smtpInsecureSkipVerify', 'Allow insecure TLS certificate verification')}</span>
                </label>
                {form.passwordSet ? (
                  <CheckboxRow
                    checked={form.passwordClear}
                    onChange={(passwordClear) => patchForm({ passwordClear, password: passwordClear ? '' : form.password })}
                    label={app.t('clearSMTPPassword', 'Clear saved SMTP password on save')}
                  />
                ) : null}
              </div>
              <div className='grid gap-2 sm:grid-cols-2 xl:grid-cols-3'>
                <CheckboxRow checked={form.notificationsEnabled} onChange={(notificationsEnabled) => patchForm({ notificationsEnabled })} label={app.t('smtpNotificationsEnabled', 'Send new alerts by email')} />
                <CheckboxRow checked={form.notifySecurity} onChange={(notifySecurity) => patchForm({ notifySecurity })} label={app.t('smtpNotifySecurity', 'Login and security failures')} />
                <CheckboxRow checked={form.notifyTasks} onChange={(notifyTasks) => patchForm({ notifyTasks })} label={app.t('smtpNotifyTasks', 'Scheduled task failures')} />
                <CheckboxRow checked={form.notifyGateways} onChange={(notifyGateways) => patchForm({ notifyGateways })} label={app.t('smtpNotifyGateways', 'Offline gateway alerts')} />
                <CheckboxRow checked={form.notifyOperations} onChange={(notifyOperations) => patchForm({ notifyOperations })} label={app.t('smtpNotifyOperations', 'Failed operation alerts')} />
                <CheckboxRow checked={form.sendExistingNotifications} onChange={(sendExistingNotifications) => patchForm({ sendExistingNotifications })} label={app.t('smtpSendExistingNotifications', 'Send current alerts on first run')} />
              </div>
              <div className='flex flex-wrap justify-end gap-2'>
                {canSaveIntegrationSettings ? (
                  <Button variant='outline' onClick={() => void saveIntegration()} disabled={saving || testing || !form.host.trim() || !form.from.trim()}>
                    <Save className='size-4' />
                    {saving ? app.t('saving', 'Saving') : app.t('save', 'Save')}
                  </Button>
                ) : null}
                {canRunSMTPTest ? (
                  <Button variant='primary' onClick={() => void testSMTP()} disabled={saving || testing || !form.host.trim() || !form.from.trim()}>
                    <Play className='size-4' />
                    {testing ? app.t('testing', 'Testing') : app.t('sendTestEmail', 'Send test')}
                  </Button>
                ) : null}
              </div>
            </section>

            <section className='grid gap-4 rounded-xl border border-border bg-background/60 p-4'>
              <div className='flex flex-wrap items-start justify-between gap-3'>
                <div>
                  <h3 className='text-sm font-semibold'>{app.t('llmIntegration', 'LLM integration')}</h3>
                  <p className='mt-1 text-xs leading-5 text-muted-foreground'>
                    {app.t('llmIntegrationDescription', 'Configure an OpenAI-compatible endpoint and send a live test prompt. API keys are encrypted server-side and never returned by API responses.')}
                  </p>
                </div>
                <Badge tone={form.llmApiKeySet ? 'success' : 'neutral'}>{form.llmApiKeySet ? app.t('apiKeySaved', 'API key saved') : app.t('notConfigured', 'Not configured')}</Badge>
              </div>
              <div className='grid gap-3 md:grid-cols-2 xl:grid-cols-4'>
                <Field label={app.t('provider', 'Provider')}>
                  <Input value={form.llmProvider} onChange={(event) => patchForm({ llmProvider: event.currentTarget.value })} placeholder='openai-compatible' />
                </Field>
                <Field className='xl:col-span-2' label={app.t('baseUrl', 'Base URL')}>
                  <Input value={form.llmBaseUrl} onChange={(event) => patchForm({ llmBaseUrl: event.currentTarget.value })} placeholder='https://api.example.com/v1' />
                </Field>
                <Field label={app.t('model', 'Model')}>
                  <Input value={form.llmModel} onChange={(event) => patchForm({ llmModel: event.currentTarget.value })} placeholder='gpt-4.1-mini' />
                </Field>
                <Field className='md:col-span-2 xl:col-span-4' label={app.t('apiKey', 'API key')}>
                  <Input type='password' value={form.llmApiKey} onChange={(event) => patchForm({ llmApiKey: event.currentTarget.value, llmApiKeyClear: false })} placeholder={form.llmApiKeySet ? app.t('leaveBlankToKeepSecret', 'Leave blank to keep current secret') : ''} autoComplete='new-password' />
                </Field>
                {form.llmApiKeySet ? (
                  <CheckboxRow
                    checked={form.llmApiKeyClear}
                    onChange={(llmApiKeyClear) => patchForm({ llmApiKeyClear, llmApiKey: llmApiKeyClear ? '' : form.llmApiKey })}
                    label={app.t('clearLLMApiKey', 'Clear saved LLM API key on save')}
                  />
                ) : null}
              </div>
              <div className='flex flex-wrap justify-end gap-2'>
                {canSaveIntegrationSettings ? (
                  <Button variant='outline' onClick={() => void saveIntegration()} disabled={saving || testing || testingLLM}>
                    <Save className='size-4' />
                    {saving ? app.t('saving', 'Saving') : app.t('save', 'Save')}
                  </Button>
                ) : null}
                {canRunLLMTest ? (
                  <Button variant='primary' onClick={() => void testLLM()} disabled={saving || testing || testingLLM || !form.llmBaseUrl.trim() || !form.llmModel.trim()}>
                    <Play className='size-4' />
                    {testingLLM ? app.t('testing', 'Testing') : app.t('testLLM', 'Test LLM')}
                  </Button>
                ) : null}
              </div>
            </section>

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

function smtpIntegrationFormFromItem(item?: PlatformItem): SMTPIntegrationForm {
  const metadata = item?.metadata || {}
  const useTLS = metadataBool(metadata.smtp_use_tls) || metadataBool(metadata.smtp_ssl) || metadataBool(metadata.tls)
  const startTLS = metadataBool(metadata.smtp_start_tls) || metadataBool(metadata.smtp_starttls) || metadataBool(metadata.start_tls) || metadataBool(metadata.starttls)
  const configuredCategories = metadataListText(metadata.smtp_notification_categories).split('\n').filter(Boolean)
  const categories = new Set(configuredCategories.length > 0 ? configuredCategories : ['security', 'task', 'gateway', 'operation'])
  return {
    host: metadataText(metadata.smtp_host) || item?.host || '',
    port: metadataText(metadata.smtp_port) || (item?.port ? String(item.port) : '587'),
    security: useTLS ? 'tls' : startTLS ? 'starttls' : 'none',
    serverName: metadataText(metadata.smtp_server_name) || metadataText(metadata.server_name),
    insecureSkipVerify: metadataBool(metadata.smtp_insecure_skip_verify) || metadataBool(metadata.insecure_skip_verify),
    username: metadataText(metadata.smtp_username) || item?.username || '',
    password: '',
    passwordSet: metadataBool(metadata.smtp_password_set),
    passwordClear: false,
    from: metadataText(metadata.smtp_from) || metadataText(metadata.from) || '',
    to: metadataText(metadata.smtp_to) || metadataText(metadata.to) || '',
    testTo: metadataText(metadata.smtp_test_to) || metadataText(metadata.test_to) || '',
    notificationsEnabled: metadataBool(metadata.smtp_notifications_enabled),
    notifySecurity: categories.has('security'),
    notifyTasks: categories.has('task'),
    notifyGateways: categories.has('gateway'),
    notifyOperations: categories.has('operation'),
    sendExistingNotifications: metadataBool(metadata.smtp_notifications_send_existing),
    llmProvider: metadataText(metadata.llm_provider),
    llmBaseUrl: metadataText(metadata.llm_base_url),
    llmModel: metadataText(metadata.llm_model),
    llmApiKey: '',
    llmApiKeySet: metadataBool(metadata.llm_api_key_set),
    llmApiKeyClear: false,
  }
}

function brandingFormFromItem(item: PlatformItem | undefined, publicConfig: PublicConfig): BrandingForm {
  const metadata = item?.metadata || {}
  const navLinks = metadata.nav_links ?? metadata.nav_links_json ?? publicConfig.nav_links
  return {
    siteName: metadataText(metadata.site_name) || metadataText(metadata.system_name) || publicConfig.site_name || '',
    logoUrl: metadataText(metadata.logo_url) || metadataText(metadata.system_icon) || publicConfig.logo_url || '',
    assetLogoUrl: metadataText(metadata.asset_logo_url) || metadataText(metadata.asset_logo) || publicConfig.asset_logo_url || '',
    githubUrl: metadataText(metadata.github_url) || publicConfig.github_url || '',
    copyright: metadataText(metadata.copyright) || publicConfig.copyright || '',
    icpNumber: metadataText(metadata.icp_number) || metadataText(metadata.icp) || publicConfig.icp_number || '',
    aboutTitle: metadataText(metadata.about_title) || publicConfig.about_title || '',
    aboutDescription: metadataText(metadata.about_description) || publicConfig.about_description || '',
    aboutBody: metadataText(metadata.about_body) || metadataText(metadata.about_content) || publicConfig.about_body || '',
    footerText: metadataText(metadata.footer_text) || publicConfig.footer_text || '',
    navLinks: formatNavLinksForForm(navLinks),
  }
}

function brandingMetadataFromForm(form: BrandingForm, previous?: Record<string, unknown>) {
  return {
    ...(previous || {}),
    site_name: form.siteName.trim(),
    logo_url: form.logoUrl.trim(),
    asset_logo_url: form.assetLogoUrl.trim(),
    github_url: form.githubUrl.trim(),
    copyright: form.copyright.trim(),
    icp_number: form.icpNumber.trim(),
    about_title: form.aboutTitle.trim(),
    about_description: form.aboutDescription.trim(),
    about_body: form.aboutBody.trim(),
    footer_text: form.footerText.trim(),
    nav_links: parseNavLinksForm(form.navLinks),
  }
}

function formatNavLinksForForm(value: unknown) {
  if (!value) {
    return JSON.stringify([
      { title: 'product', href: '/#product' },
      { title: 'connections', href: '/#connections' },
      { title: 'security', href: '/#security' },
      { title: 'deploy', href: '/#deploy' },
      { title: 'about', href: '/about' },
    ], null, 2)
  }
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed) return formatNavLinksForForm(null)
    try {
      return JSON.stringify(JSON.parse(trimmed), null, 2)
    } catch {
      return trimmed
    }
  }
  return JSON.stringify(value, null, 2)
}

function parseNavLinksForm(value: string) {
  const trimmed = value.trim()
  if (!trimmed) return []
  try {
    const parsed = JSON.parse(trimmed) as unknown
    if (Array.isArray(parsed)) {
      return parsed.map((item) => {
        const raw = item as Record<string, unknown>
        return {
          title: metadataText(raw.title) || metadataText(raw.label) || metadataText(raw.name),
          href: metadataText(raw.href) || metadataText(raw.url) || metadataText(raw.path),
          external: metadataBool(raw.external),
        }
      }).filter((item) => item.title && item.href)
    }
  } catch {
    return []
  }
  return []
}

function proxyServicesFormFromItem(item?: PlatformItem): ProxyServicesForm {
  const metadata = item?.metadata || {}
  return {
    sshEnabled: metadataBool(metadata.ssh_gateway_enabled),
    sshListenAddress: metadataText(metadata.ssh_listen_address) || metadataText(metadata.listen_address) || '0.0.0.0:2022',
    sshDisablePasswordAuth: metadataBool(metadata.ssh_disable_password_auth) || metadataBool(metadata.disable_password_auth),
    sshForwardAllowlist: metadataListText(metadata.ssh_forward_allowlist || metadata.forward_allowlist),
    rdpEnabled: metadataBool(metadata.rdp_proxy_enabled),
    rdpListenAddress: metadataText(metadata.rdp_listen_address) || '0.0.0.0:23389',
    rdpForwardAllowlist: metadataListText(metadata.rdp_forward_allowlist),
    databaseEnabled: metadataBool(metadata.database_proxy_enabled),
    databaseListenAddress: metadataText(metadata.database_listen_address) || '127.0.0.1:23306',
    databaseForwardAllowlist: metadataListText(metadata.database_forward_allowlist),
    proxyPrivateKey: '',
    proxyPrivateKeySet: metadataBool(metadata.proxy_private_key_set),
    proxyPrivateKeyClear: false,
  }
}

function proxyServicesPayloadFromForm(form: ProxyServicesForm) {
  return {
    ssh_enabled: form.sshEnabled,
    ssh_listen_address: form.sshListenAddress.trim(),
    ssh_disable_password_auth: form.sshDisablePasswordAuth,
    ssh_forward_allowlist: splitLines(form.sshForwardAllowlist),
    rdp_enabled: form.rdpEnabled,
    rdp_listen_address: form.rdpListenAddress.trim(),
    rdp_forward_allowlist: splitLines(form.rdpForwardAllowlist),
    database_enabled: form.databaseEnabled,
    database_listen_address: form.databaseListenAddress.trim(),
    database_forward_allowlist: splitLines(form.databaseForwardAllowlist),
    proxy_private_key: form.proxyPrivateKey.trim() || undefined,
    proxy_private_key_clear: form.proxyPrivateKeyClear || undefined,
  }
}

function proxyRoutes(value: unknown): ProxyRouteStatus[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((item) => {
    if (!item || typeof item !== 'object') return []
    const record = item as Record<string, unknown>
    const listenAddress = metadataText(record.listen_address)
    const target = metadataText(record.target)
    return listenAddress && target ? [{ listen_address: listenAddress, target }] : []
  })
}

function ProxyRouteList({ routes }: { routes: ProxyRouteStatus[] }) {
  const app = useApp()
  if (!routes.length) return null
  return (
    <div className='mt-2 grid gap-1.5 border-t border-border pt-2'>
      <div className='font-medium text-foreground'>{app.t('listenerMappings', 'Listener mappings')}</div>
      {routes.map((route) => (
        <div key={`${route.listen_address}-${route.target}`} className='grid min-w-0 grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-center gap-2 rounded-md border border-border px-2 py-1.5 font-mono'>
          <span className='min-w-0 break-all text-foreground'>{route.listen_address}</span>
          <MoveRight className='size-3.5 shrink-0' aria-hidden='true' />
          <span className='min-w-0 break-all text-foreground'>{route.target}</span>
        </div>
      ))}
    </div>
  )
}

function metadataListText(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item).trim()).filter(Boolean).join('\n')
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed) return ''
    try {
      const parsed = JSON.parse(trimmed) as unknown
      if (Array.isArray(parsed)) return parsed.map((item) => String(item).trim()).filter(Boolean).join('\n')
    } catch {
      // Plain newline/comma separated text is accepted below.
    }
    return trimmed.split(/[\n,;]+/).map((item) => item.trim()).filter(Boolean).join('\n')
  }
  return ''
}

function proxyStateTone(status: Record<string, unknown> | undefined) {
  const state = metadataText(status?.state)
  if (['running', 'online', 'configured', 'ready'].includes(state)) return 'success'
  if (state === 'disabled' || !state) return 'neutral'
  return 'warning'
}

function desktopAccessFormFromItem(item?: PlatformItem): DesktopAccessForm {
  const metadata = item?.metadata || {}
  return {
    width: metadataText(metadata.desktop_width) || '1440',
    height: metadataText(metadata.desktop_height) || '900',
    dpi: metadataText(metadata.desktop_dpi) || '96',
    colorDepth: metadataText(metadata.desktop_color_depth) || '24',
    resizeMethod: metadataText(metadata.desktop_resize_method) || 'display-update',
    recordingEnabled: metadataBool(metadata.desktop_recording_enabled),
    clipboardEnabled: metadata.desktop_clipboard_enabled === undefined ? true : metadataBool(metadata.desktop_clipboard_enabled),
    fileTransferEnabled: metadata.rdp_file_transfer_enabled === undefined && metadata.desktop_file_transfer_enabled === undefined
      ? true
      : metadataBool(metadata.rdp_file_transfer_enabled ?? metadata.desktop_file_transfer_enabled),
    sshFileTransferEnabled: metadata.ssh_file_transfer_enabled === undefined ? true : metadataBool(metadata.ssh_file_transfer_enabled),
    ignoreCert: metadata.desktop_ignore_cert === undefined ? true : metadataBool(metadata.desktop_ignore_cert),
    readOnly: metadataBool(metadata.desktop_read_only),
    watermarkEnabled: metadataBool(metadata.watermark_enabled),
    watermarkText: metadataText(metadata.watermark_text),
    watermarkColor: metadataText(metadata.watermark_color) || 'rgba(255,255,255,0.18)',
    watermarkFontSize: metadataText(metadata.watermark_font_size) || '28',
    accessMfaEnabled: metadataBool(metadata.access_mfa_enabled ?? metadata.access_mfa_required),
    accessMfaValidMinutes: metadataText(metadata.access_mfa_valid_minutes) || '10',
  }
}

function desktopAccessMetadataFromForm(form: DesktopAccessForm, existing?: Record<string, unknown>) {
  const metadata: Record<string, unknown> = { ...(existing || {}) }
  metadata.desktop_width = Number(form.width) || 1440
  metadata.desktop_height = Number(form.height) || 900
  metadata.desktop_dpi = Number(form.dpi) || 96
  metadata.desktop_color_depth = Number(form.colorDepth) || 24
  metadata.desktop_resize_method = form.resizeMethod || 'display-update'
  metadata.desktop_recording_enabled = form.recordingEnabled
  metadata.desktop_clipboard_enabled = form.clipboardEnabled
  metadata.rdp_file_transfer_enabled = form.fileTransferEnabled
  metadata.ssh_file_transfer_enabled = form.sshFileTransferEnabled
  metadata.desktop_ignore_cert = form.ignoreCert
  metadata.desktop_read_only = form.readOnly
  metadata.watermark_enabled = form.watermarkEnabled
  metadata.watermark_text = form.watermarkText.trim()
  metadata.watermark_color = form.watermarkColor.trim() || 'rgba(255,255,255,0.18)'
  metadata.watermark_font_size = Number(form.watermarkFontSize) || 28
  metadata.access_mfa_enabled = form.accessMfaEnabled
  metadata.access_mfa_valid_minutes = Number(form.accessMfaValidMinutes) || 10
  return metadata
}

function integrationMetadataFromForm(form: SMTPIntegrationForm, existing?: Record<string, unknown>) {
  const metadata: Record<string, unknown> = { ...(existing || {}) }
  metadata.smtp_host = form.host.trim()
  metadata.smtp_port = form.port ? Number(form.port) : 587
  metadata.smtp_username = form.username.trim()
  metadata.smtp_from = form.from.trim()
  metadata.smtp_to = form.to.trim()
  metadata.smtp_test_to = form.testTo.trim()
  metadata.smtp_use_tls = form.security === 'tls'
  metadata.smtp_start_tls = form.security === 'starttls'
  metadata.smtp_server_name = form.serverName.trim()
  metadata.smtp_insecure_skip_verify = form.insecureSkipVerify
  metadata.smtp_notifications_enabled = form.notificationsEnabled
  metadata.smtp_notification_categories = [
    form.notifySecurity ? 'security' : '',
    form.notifyTasks ? 'task' : '',
    form.notifyGateways ? 'gateway' : '',
    form.notifyOperations ? 'operation' : '',
  ].filter(Boolean)
  metadata.smtp_notifications_send_existing = form.sendExistingNotifications
  if (form.passwordClear) metadata.smtp_password_clear = true
  metadata.llm_provider = form.llmProvider.trim()
  metadata.llm_base_url = form.llmBaseUrl.trim()
  metadata.llm_model = form.llmModel.trim()
  if (form.llmApiKey.trim()) metadata.llm_api_key = form.llmApiKey.trim()
  if (form.llmApiKeyClear) metadata.llm_api_key_clear = true
  return metadata
}

async function ensureAccessMFA(path: string, requestAccessMFACode: RequestAccessMFACode) {
  const verify = (mfaCode = '') => apiRequest<{ ok?: boolean }>(path, {
    method: 'POST',
    body: JSON.stringify(mfaCode ? { mfa_code: mfaCode } : {}),
  })
  try {
    await verify()
    return true
  } catch (error) {
    if (!isAccessMFARequiredError(error)) throw error
    const mfaCode = await requestAccessMFACode()
    if (!mfaCode) return false
    await verify(mfaCode)
    return true
  }
}

function openAccessPopup() {
  const popup = window.open('about:blank', '_blank')
  if (popup) popup.opener = null
  return popup
}

export function AccessPortalPage() {
  const app = useApp()
  const [databaseQueryItem, setDatabaseQueryItem] = useState<PlatformItem | null>(null)
  const { requestAccessMFACode, accessMFADialog } = useAccessMFADialog()
  const accessAssetsQuery = useQuery({
    queryKey: ['access-assets'],
    queryFn: () => apiRequest<AccessAssetsResponse>('/api/access/assets'),
    staleTime: 10_000,
  })
  const textAssets = accessAssetsQuery.data?.text || []
  const desktopAssets = accessAssetsQuery.data?.desktop || []
  const webAssets = accessAssetsQuery.data?.web || []
  const databaseAssets = accessAssetsQuery.data?.database || []
  const assetsPage = platformPageByRoute('/app/assets')
  const canManageAssets = assetsPage ? canViewPlatformPage(app.auth?.role, assetsPage, app.auth?.menu_permissions) : false
  return (
    <div className='grid gap-4'>
      <section className='rounded-2xl border border-border bg-card p-5'>
        <div className='flex flex-wrap items-start justify-between gap-3'>
          <div>
            <p className='text-xs font-medium tracking-[0.14em] text-muted-foreground uppercase'>{app.t('accessPage.eyebrow')}</p>
            <h1 className='mt-2 text-2xl font-semibold tracking-tight'>{app.t('accessPage.title')}</h1>
            <p className='mt-2 max-w-2xl text-sm leading-6 text-muted-foreground'>{app.t('accessPage.description')}</p>
          </div>
          {canManageAssets ? (
            <Link to={'/app/assets' as never} className='inline-flex h-8 items-center gap-2 rounded-lg border border-border px-3 text-sm hover:bg-muted'>
              {app.t('accessPage.manageAssets')}
              <ArrowUpRight className='size-4' />
            </Link>
          ) : null}
        </div>
      </section>
      {accessAssetsQuery.isLoading ? (
        <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>
          {app.t('loading', 'Loading...')}
        </div>
      ) : accessAssetsQuery.isError ? (
        <div className='rounded-xl border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive'>
          {app.t('accessAssetsLoadFailed', 'Access assets could not be loaded.')}
        </div>
      ) : (
        <>
          <AccessSection title={app.t('accessPage.textProtocols')} items={textAssets} requestAccessMFACode={requestAccessMFACode} />
          <AccessSection title={app.t('accessPage.desktopProtocols')} items={desktopAssets} requestAccessMFACode={requestAccessMFACode} />
          <AccessSection title={app.t('accessPage.webAssets')} items={webAssets} protocol='http' requestAccessMFACode={requestAccessMFACode} />
          <AccessSection title={app.t('accessPage.databaseAssets')} items={databaseAssets} protocol='database' onDatabaseQuery={setDatabaseQueryItem} requestAccessMFACode={requestAccessMFACode} />
        </>
      )}
      {databaseQueryItem ? (
        <SQLExecuteDialog
          item={databaseQueryItem}
          requestAccessMFACode={requestAccessMFACode}
          endpoint={`/api/access/database/${databaseQueryItem.id}/query`}
          workOrderEndpoint={`/api/access/database/${databaseQueryItem.id}/work-orders`}
          initialSQL={stringValue(databaseQueryItem.metadata?.sql) || 'SELECT name FROM sqlite_master WHERE type = "table";'}
          successMessage={app.t('accessPage.sqlExecuted')}
          workOrderMessage={app.t('accessPage.sqlWorkOrderSubmitted')}
          description={app.t('accessPage.sqlDescription')}
          onClose={() => setDatabaseQueryItem(null)}
        />
      ) : null}
      {accessMFADialog}
    </div>
  )
}

function AccessSection({
  title,
  items,
  protocol,
  onDatabaseQuery,
  requestAccessMFACode,
}: {
  title: string
  items: PlatformItem[]
  protocol?: string
  onDatabaseQuery?: (item: PlatformItem) => void
  requestAccessMFACode: RequestAccessMFACode
}) {
  const app = useApp()
  const [sshExecItem, setSSHExecItem] = useState<PlatformItem | null>(null)
  const connect = async (item: PlatformItem) => {
    const accessProtocol = (protocol || item.protocol || 'ssh') as Protocol
    if (accessProtocol === 'http') {
      const popup = openAccessPopup()
      if (!popup) {
        app.showToast(app.t('accessPage.popupBlocked'))
        return
      }
      try {
        if (!(await ensureAccessMFA(`/api/access/http/${item.id}/mfa`, requestAccessMFACode))) {
          popup.close()
          return
        }
        popup.location.replace(`/api/access/http/${item.id}/proxy/`)
      } catch (error) {
        popup.close()
        app.handleApiError(error)
      }
      return
    }
    if (accessProtocol === 'database') {
      onDatabaseQuery?.(item)
      return
    }
    try {
      const payload: Record<string, unknown> = accessProtocol === 'rdp' || accessProtocol === 'vnc'
        ? {
          width: Math.max(1024, window.innerWidth),
          height: Math.max(680, window.innerHeight - 52),
          dpi: 96,
        }
        : {
          cols: 120,
          rows: 32,
          term: 'xterm-256color',
        }
      const createSession = (mfaCode = '') => apiRequest<ConnectionSession>(`/api/access/${accessProtocol}/${item.id}`, {
        method: 'POST',
        body: JSON.stringify(mfaCode ? { ...payload, mfa_code: mfaCode } : payload),
      })
      let session: ConnectionSession
      try {
        session = await createSession()
      } catch (error) {
        if (!isAccessMFARequiredError(error)) throw error
        const mfaCode = await requestAccessMFACode()
        if (!mfaCode) return
        session = await createSession(mfaCode)
      }
      if (accessProtocol === 'ssh' || accessProtocol === 'rdp' || accessProtocol === 'vnc') {
        app.setWorkspace({ type: accessProtocol, session, status: 'connecting' })
      } else {
        await app.refresh(true)
        app.showToast(app.t('accessPage.sessionCreated'))
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
                {app.t('accessPage.connect')}
              </Button>
              {(protocol || item.protocol) === 'ssh' ? (
                <Button className='mt-2 w-full' variant='outline' size='sm' onClick={() => setSSHExecItem(item)}>
                  <TerminalSquare className='size-4' />
                  Exec
                </Button>
              ) : null}
            </article>
          ))}
        </div>
      ) : (
        <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>{app.t('accessPage.noAuthorizedResources')}</div>
      )}
      {sshExecItem ? <SSHExecDialog item={sshExecItem} onClose={() => setSSHExecItem(null)} requestAccessMFACode={requestAccessMFACode} /> : null}
    </section>
  )
}

function ToolsPage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const apiPath = config.apiPath || '/api/tools/ping'
  const role = app.auth?.role
  const apiPermissions = app.auth?.api_permissions || []
  const canRunTool = canUseAPI(role, apiPermissions, 'POST', apiPath)
  const [target, setTarget] = useState('')
  const [mode, setMode] = useState<'icmp' | 'tcp'>('icmp')
  const [count, setCount] = useState('4')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<PingToolResponse | null>(null)
  const run = async () => {
    if (!canRunTool) return
    setLoading(true)
    try {
      const data = await apiRequest<PingToolResponse>(apiPath, {
        method: 'POST',
        body: JSON.stringify({ target, count: Number(count) || 4, mode }),
      })
      setResult(data)
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoading(false)
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
        {canRunTool ? (
          <div className='grid gap-3 md:grid-cols-[minmax(0,1fr)_10rem_7rem_auto]'>
            <Input placeholder={mode === 'tcp' ? 'host:port' : 'IP / domain'} value={target} onChange={(event) => setTarget(event.currentTarget.value)} />
            <Select value={mode} onChange={(event) => setMode(event.currentTarget.value as 'icmp' | 'tcp')}>
              <option value='icmp'>Ping</option>
              <option value='tcp'>TCP Ping</option>
            </Select>
            <Input type='number' min={1} max={10} value={count} onChange={(event) => setCount(event.currentTarget.value)} aria-label='count' />
            <Button variant='primary' onClick={() => void run()} disabled={!target.trim() || loading}>
              <Play className={cn('size-4', loading && 'animate-pulse')} />
              {loading ? '检测中' : '开始检测'}
            </Button>
          </div>
        ) : (
          <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>当前账号没有执行诊断工具的 API 权限。</div>
        )}
        {result ? (
          <div className='grid gap-3'>
            <div className='flex flex-wrap items-center gap-2 text-sm'>
              <Badge tone='neutral'>{result.mode}</Badge>
              <Badge tone='success'>OK {numberValue(result.summary?.ok)}</Badge>
              <Badge tone={numberValue(result.summary?.failed) > 0 ? 'danger' : 'neutral'}>Failed {numberValue(result.summary?.failed)}</Badge>
              <span className='font-mono text-xs text-muted-foreground'>{result.target}</span>
            </div>
            <div className='overflow-hidden rounded-xl border border-border bg-background/60'>
              {result.results.map((row) => (
                <div key={row.seq} className='grid gap-2 border-b border-border px-3 py-2 text-sm last:border-b-0 md:grid-cols-[3rem_5rem_7rem_minmax(0,1fr)] md:items-center'>
                  <span className='font-mono text-xs text-muted-foreground'>#{row.seq}</span>
                  <Badge tone={row.status === 'ok' ? 'success' : 'danger'}>{row.status}</Badge>
                  <span className='font-mono text-xs'>{numberValue(row.latency_ms ?? row.latency)} ms</span>
                  <div className='min-w-0'>
                    <div className='truncate font-mono text-xs'>{row.address || row.target}</div>
                    <div className='truncate text-xs text-muted-foreground'>{row.detail || '-'}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>暂无检测结果</div>
        )}
      </CardContent>
    </Card>
  )
}

function MonitoringPage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const apiPath = config.apiPath || '/api/system/monitoring'
  const role = app.auth?.role
  const apiPermissions = app.auth?.api_permissions || []
  const canReadMonitoring = canUseAPI(role, apiPermissions, 'GET', apiPath)
  const [monitor, setMonitor] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(false)
  const load = async () => {
    if (!canReadMonitoring) return
    setLoading(true)
    try {
      setMonitor(await apiRequest<Record<string, unknown>>(apiPath))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (!canReadMonitoring) return
    void load()
  }, [apiPath, canReadMonitoring])

  const stats = monitor || {
    users: app.data.platform?.users?.length || 0,
    assets: app.data.platform?.assets?.length || 0,
    web_assets: app.data.platform?.web_assets?.length || 0,
    database_assets: app.data.platform?.database_assets?.length || 0,
    active_sessions: app.data.platform?.online_sessions?.length || 0,
    recordings: app.data.platform?.offline_sessions?.length || 0,
  }
  const runtimeInfo = recordValue(stats.runtime)
  const memoryInfo = recordValue(stats.memory)
  const databaseInfo = recordValue(stats.database)
  const storageInfo = recordValue(stats.storage)
  const sshGatewayInfo = recordValue(stats.ssh_gateway)
  const guacdInfo = recordValue(stats.guacd)
	const recordingTranscoderInfo = recordValue(stats.recording_transcoder)
  const agentGatewayInfo = recordValue(stats.agent_gateways)
  const dataDirInfo = recordValue(storageInfo.data_dir)
  const recordingsInfo = recordValue(storageInfo.recordings)
  const drivesInfo = recordValue(storageInfo.drives)
  const backupsInfo = recordValue(storageInfo.backups)
  const metricCards = [
    ['Status', metadataText(stats.status) || 'normal', metadataText(stats.status) === 'normal' ? 'success' : 'neutral'],
    ['Users', formatNumberValue(stats.users), 'neutral'],
    ['Assets', formatNumberValue(stats.assets), 'neutral'],
    ['Active sessions', formatNumberValue(stats.active_sessions), 'success'],
    ['Recordings', formatNumberValue(stats.recordings), 'neutral'],
    ['Gateways', formatNumberValue(stats.gateways), 'neutral'],
    ['Goroutines', formatNumberValue(stats.goroutines), 'neutral'],
    ['Memory', formatBytesValue(stats.memory_alloc), 'neutral'],
  ] as const
  const runtimeRows: Array<[string, string]> = [
    ['Uptime', `${formatNumberValue(stats.uptime_seconds)} s`],
    ['Go', metadataText(runtimeInfo.go_version || stats.go_version) || '-'],
    ['OS / Arch', `${metadataText(runtimeInfo.os || stats.os) || '-'} / ${metadataText(runtimeInfo.arch || stats.arch) || '-'}`],
    ['CPU cores', formatNumberValue(runtimeInfo.cpu_cores || stats.cpu_cores || stats.cpu)],
    ['Heap alloc', formatBytesValue(memoryInfo.heap_alloc || stats.memory_heap_alloc)],
    ['GC count', formatNumberValue(memoryInfo.gc_count || stats.gc_count)],
    ['DB pool', metadataText(databaseInfo.connection_pool_state) || '-'],
    ['DB connections', `${formatNumberValue(databaseInfo.in_use)} in use / ${formatNumberValue(databaseInfo.idle)} idle`],
  ]
  const gatewayRows: Array<[string, string]> = [
    ['SSH Gateway', `${metadataText(sshGatewayInfo.status) || 'disabled'} ${metadataText(sshGatewayInfo.address)}`.trim()],
    ['guacd', `${metadataText(guacdInfo.status) || 'unavailable'} ${metadataText(guacdInfo.address)}`.trim()],
		['Recording transcoder', `${metadataText(recordingTranscoderInfo.status) || 'unavailable'} ${metadataText(recordingTranscoderInfo.detail)}`.trim()],
    ['Agent gateways', `${formatNumberValue(agentGatewayInfo.online)} online / ${formatNumberValue(agentGatewayInfo.offline)} offline`],
  ]
  const storageRows: Array<[string, string]> = [
    ['Data dir', `${formatBytesValue(dataDirInfo.bytes)} / ${formatNumberValue(dataDirInfo.files)} files`],
    ['Recordings', `${formatBytesValue(recordingsInfo.bytes)} / ${formatNumberValue(recordingsInfo.files)} files`],
    ['Drives', `${formatBytesValue(drivesInfo.bytes)} / ${formatNumberValue(drivesInfo.files)} files`],
    ['Backups', `${formatBytesValue(backupsInfo.bytes)} / ${formatNumberValue(backupsInfo.files)} files`],
  ]
  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>系统监控</CardTitle>
          <CardDescription>集中查看服务、网关、会话、存储和告警的运行状态。</CardDescription>
        </div>
        {canReadMonitoring ? (
          <Button variant='outline' onClick={() => void load()} disabled={loading}>
            <RefreshCw className={cn('size-4', loading && 'animate-spin')} />
            刷新
          </Button>
        ) : null}
      </CardHeader>
      <CardContent className='grid gap-5'>
        {canReadMonitoring ? (
          <>
            <div className='grid gap-3 md:grid-cols-3 xl:grid-cols-4'>
              {metricCards.map(([label, value, tone]) => (
                <div key={label} className='rounded-xl border border-border bg-background/60 p-4'>
                  <div className='text-xs font-medium text-muted-foreground'>{label}</div>
                  <div className={cn('mt-2 truncate font-mono text-xl font-semibold', tone === 'success' && 'text-success')}>{value}</div>
                </div>
              ))}
            </div>
            <div className='grid gap-3 lg:grid-cols-3'>
              <MonitoringPanel title='Runtime / Database' rows={runtimeRows} />
              <MonitoringPanel title='Gateways' rows={gatewayRows} />
              <MonitoringPanel title='Storage' rows={storageRows} />
            </div>
          </>
        ) : (
          <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>当前账号没有读取系统监控的 API 权限。</div>
        )}
      </CardContent>
    </Card>
  )
}

function MonitoringPanel({ title, rows }: { title: string; rows: Array<[string, string]> }) {
  return (
    <section className='rounded-xl border border-border bg-background/60 p-4'>
      <h3 className='text-sm font-semibold'>{title}</h3>
      <div className='mt-3 grid gap-2'>
        {rows.map(([label, value]) => (
          <div key={label} className='grid grid-cols-[7rem_minmax(0,1fr)] gap-3 text-sm'>
            <span className='text-muted-foreground'>{label}</span>
            <span className='truncate font-mono text-xs'>{value || '-'}</span>
          </div>
        ))}
      </div>
    </section>
  )
}

function BackupsPage({ config }: { config: PlatformPageConfig }) {
  const app = useApp()
  const label = platformLabel(config, app.locale)
  const description = platformDescription(config, app.locale)
  const Icon = config.icon
  const { confirm, confirmDialog } = useConfirmDialog()
  const apiPath = config.apiPath || '/api/admin/backups'
  const role = app.auth?.role
  const apiPermissions = app.auth?.api_permissions || []
  const canUsePath: CanUsePath = (method, path) => canUseAPI(role, apiPermissions, method, path)
  const canListBackups = canUsePath('GET', apiPath)
  const canCreateBackup = canUsePath('POST', apiPath)
  const canRestoreBackup = canUsePath('POST', `${apiPath}/restore`)
  const canDownloadBackup = (item: BackupInfo) => canUsePath('GET', `${apiPath}/${encodeURIComponent(item.name)}/download`)
  const canDeleteBackup = (item: BackupInfo) => canUsePath('DELETE', `${apiPath}/${encodeURIComponent(item.name)}`)
  const [items, setItems] = useState<BackupInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [creating, setCreating] = useState(false)
  const [restoring, setRestoring] = useState(false)
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [validation, setValidation] = useState<Record<string, unknown> | null>(null)

  const load = async () => {
    if (!canListBackups) return
    setLoading(true)
    try {
      const data = await apiRequest<{ items: BackupInfo[] }>(apiPath)
      setItems(data.items || [])
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [apiPath, canListBackups])

  const createBackup = async () => {
    if (!canCreateBackup) return
    setCreating(true)
    try {
      await apiRequest(apiPath, { method: 'POST', body: '{}' })
      await load()
      app.showToast('备份已创建')
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setCreating(false)
    }
  }

  const validateUpload = async () => {
    if (!canRestoreBackup || !uploadFile) return
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
    if (!canRestoreBackup || !uploadFile) return
    const confirmed = await confirm({
      title: '恢复备份并覆盖当前数据?',
      description: '恢复会覆盖当前系统数据，并在恢复前自动创建一份当前备份。恢复完成后需要重新登录。',
      confirmText: '恢复',
      destructive: true,
    })
    if (!confirmed) return
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

  const deleteBackup = async (item: BackupInfo) => {
    if (!canDeleteBackup(item)) return
    const confirmed = await confirm({
      title: `删除备份 ${item.name}?`,
      description: '备份文件删除后不可恢复。',
      confirmText: '删除',
      destructive: true,
    })
    if (!confirmed) return
    try {
      await apiRequest(`${apiPath}/${encodeURIComponent(item.name)}`, { method: 'DELETE' })
      await load()
      app.showToast('备份已删除')
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
              {canListBackups ? (
                <Button variant='outline' onClick={() => void load()} disabled={loading}>
                  <RefreshCw className={cn('size-4', loading && 'animate-spin')} />
                  刷新
                </Button>
              ) : null}
              {canCreateBackup ? (
                <Button variant='primary' onClick={() => void createBackup()} disabled={creating}>
                  <Save className='size-4' />
                  {creating ? '备份中' : '立即备份'}
                </Button>
              ) : null}
            </div>
          </CardHeader>
          <CardContent className='grid gap-5'>
            {canRestoreBackup ? (
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
            ) : null}
            {canListBackups ? (
              <div className='grid gap-3'>
                {items.length ? items.map((item) => {
                  const canDownload = canDownloadBackup(item)
                  const canDelete = canDeleteBackup(item)
                  return (
                <article key={item.name} className='grid gap-3 rounded-xl border border-border bg-background/60 p-4 md:grid-cols-[minmax(0,1fr)_auto] md:items-center'>
                  <div className='min-w-0'>
                    <div className='flex flex-wrap items-center gap-2'>
                      <h3 className='truncate text-sm font-semibold'>{item.name}</h3>
                      <Badge tone='neutral'>{formatBytesValue(item.size)}</Badge>
                    </div>
                    <p className='mt-1 text-xs text-muted-foreground'>{formatDate(item.modified_at)} · {(item.files || []).join(', ') || 'manifest only'}</p>
                  </div>
                  <div className='flex flex-wrap justify-end gap-2 md:flex-nowrap'>
                    {canDownload ? (
                      <Button variant='outline' onClick={() => void downloadResponse(`${apiPath}/${encodeURIComponent(item.name)}/download`, item.name)}>
                        <Download className='size-4' />
                        下载
                      </Button>
                    ) : null}
                    {canDelete ? (
                      <Button variant='destructive' onClick={() => void deleteBackup(item)}>
                        <Trash2 className='size-4' />
                        删除
                      </Button>
                    ) : null}
                  </div>
                </article>
                  )
                }) : (
                  <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>暂无备份。点击“立即备份”生成第一份快照。</div>
                )}
              </div>
            ) : (
              <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>当前账号没有查看备份列表的 API 权限。</div>
            )}
          </CardContent>
        </Card>
      </CardStaggerItem>
      {confirmDialog}
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
  const apiPath = config.apiPath || '/api/admin/audit/access-stats'
  const role = app.auth?.role
  const apiPermissions = app.auth?.api_permissions || []
  const canReadStats = canUseAPI(role, apiPermissions, 'GET', apiPath)
  const [items, setItems] = useState<PlatformItem[]>([])
  const [loading, setLoading] = useState(false)

  const load = async () => {
    if (!canReadStats) return
    setLoading(true)
    try {
      const data = await apiRequest<{ items: PlatformItem[] }>(apiPath)
      setItems(data.items || [])
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [apiPath, canReadStats])

  const summary = items.find((item) => item.type === 'summary')
  const summaryMetadata = summary?.metadata || {}
  const metrics = [
    { label: 'PV', value: formatNumberValue(summaryMetadata.pv) },
    { label: 'UV', value: formatNumberValue(summaryMetadata.uv) },
    { label: app.t('accessStats.uniqueIPs', 'Unique IPs'), value: formatNumberValue(summaryMetadata.unique_ips) },
    { label: app.t('accessStats.requestCount', 'Requests'), value: formatNumberValue(summaryMetadata.request_count) },
    { label: app.t('accessStats.traffic', 'Traffic'), value: formatBytesValue(summaryMetadata.traffic_bytes) },
    { label: app.t('accessStats.averageDuration', 'Avg duration'), value: `${formatNumberValue(summaryMetadata.average_duration_ms)} ms` },
    { label: app.t('accessStats.errorRate', 'Error rate'), value: formatPercentValue(summaryMetadata.error_rate) },
    { label: app.t('accessStats.errorCount', 'Errors'), value: formatNumberValue(summaryMetadata.error_count) },
  ]
  const sections = [
    { type: 'top_pages', title: app.t('accessStats.topPages', 'Top pages') },
    { type: 'referrers', title: app.t('accessStats.referrers', 'Referrers') },
    { type: 'assets', title: app.t('accessStats.assets', 'Assets') },
    { type: 'status_codes', title: app.t('accessStats.statusCodes', 'Status codes') },
    { type: 'methods', title: app.t('accessStats.methods', 'Methods') },
  ]
  const emptyStatsLabel = app.t('accessStats.noData', 'No access statistics yet.')

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
            {canReadStats ? (
              <Button variant='outline' onClick={() => void load()} disabled={loading}>
                <RefreshCw className={cn('size-4', loading && 'animate-spin')} />
                {app.t('refresh', 'Refresh')}
              </Button>
            ) : null}
          </CardHeader>
          <CardContent className='grid gap-5'>
            {canReadStats ? (
              <>
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
                    <AccessStatsRank key={section.type} title={section.title} item={items.find((entry) => entry.type === section.type)} emptyLabel={emptyStatsLabel} />
                  ))}
                </div>
              </>
            ) : (
              <div className='rounded-xl border border-dashed border-border p-6 text-sm text-muted-foreground'>当前账号没有读取访问统计的 API 权限。</div>
            )}
          </CardContent>
        </Card>
      </CardStaggerItem>
    </CardStaggerContainer>
  )
}

function AccessStatsRank({ title, item, emptyLabel }: { title: string; item?: PlatformItem; emptyLabel: string }) {
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
          <div className='rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground'>{emptyLabel}</div>
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

function splitWords(value: string) {
  return value.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean)
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

function buildDepartmentTree(items: PlatformItem[]): DepartmentTreeNode[] {
  const idByKey = new Map<string, string>()
  const byParent = new Map<string, PlatformItem[]>()
  const visited = new Set<string>()

  for (const item of items) {
    for (const value of [item.id, item.name]) {
      const key = departmentTreeKey(value)
      if (key && !idByKey.has(key)) idByKey.set(key, item.id)
    }
  }

  for (const item of items) {
    const parentKey = departmentTreeKey(item.parent_id)
    const parentID = parentKey ? idByKey.get(parentKey) || item.parent_id : ''
    const safeParentID = parentID && parentID !== item.id ? parentID : ''
    const siblings = byParent.get(safeParentID) || []
    siblings.push(item)
    byParent.set(safeParentID, siblings)
  }

  for (const siblings of byParent.values()) {
    siblings.sort(departmentTreeSort)
  }

  const build = (parentID: string): DepartmentTreeNode[] => {
    const siblings = byParent.get(parentID) || []
    return siblings
      .filter((item) => {
        if (visited.has(item.id)) return false
        visited.add(item.id)
        return true
      })
      .map((item) => ({ item, children: build(item.id) }))
  }

  const roots = build('')
  for (const item of [...items].sort(departmentTreeSort)) {
    if (!visited.has(item.id)) {
      visited.add(item.id)
      roots.push({ item, children: build(item.id) })
    }
  }
  return roots
}

function departmentTreeKey(value: unknown) {
  return metadataText(value).trim().toLowerCase()
}

function departmentTreeSort(left: PlatformItem, right: PlatformItem) {
  const leftSort = metadataNumber(left.metadata?.sort)
  const rightSort = metadataNumber(right.metadata?.sort)
  if (leftSort !== rightSort) return leftSort - rightSort
  return left.name.localeCompare(right.name, undefined, { numeric: true, sensitivity: 'base' })
}

function buildAssetGroupTree(groups: PlatformItem[], assets: PlatformItem[]): AssetGroupTreeNode[] {
  const idByKey = new Map<string, string>()
  const byParent = new Map<string, PlatformItem[]>()
  const visited = new Set<string>()

  for (const group of groups) {
    for (const value of [group.id, group.name]) {
      const key = assetGroupKey(value)
      if (key && !idByKey.has(key)) idByKey.set(key, group.id)
    }
  }

  for (const group of groups) {
    const parentKey = assetGroupKey(group.parent_id)
    const parentID = parentKey ? idByKey.get(parentKey) || group.parent_id : ''
    const safeParentID = parentID && parentID !== group.id ? parentID : ''
    const siblings = byParent.get(safeParentID) || []
    siblings.push(group)
    byParent.set(safeParentID, siblings)
  }

  for (const siblings of byParent.values()) {
    siblings.sort(assetGroupTreeSort)
  }

  const build = (parentID: string): AssetGroupTreeNode[] => {
    const siblings = byParent.get(parentID) || []
    return siblings
      .filter((group) => {
        if (visited.has(group.id)) return false
        visited.add(group.id)
        return true
      })
      .map((group) => buildAssetGroupNode(group, build(group.id), assets))
  }

  const roots = build('')
  for (const group of [...groups].sort(assetGroupTreeSort)) {
    if (!visited.has(group.id)) {
      visited.add(group.id)
      roots.push(buildAssetGroupNode(group, build(group.id), assets))
    }
  }
  return roots
}

function buildAssetGroupNode(group: PlatformItem, children: AssetGroupTreeNode[], assets: PlatformItem[]): AssetGroupTreeNode {
  const directAssetIDs = assetGroupAssetIDs(group, assets)
  const assetIDs = new Set(directAssetIDs)
  for (const child of children) {
    for (const assetID of child.assetIDs) assetIDs.add(assetID)
  }
  return {
    item: group,
    children,
    directAssetCount: directAssetIDs.size,
    totalAssetCount: assetIDs.size,
    assetIDs,
  }
}

function assetGroupTreeSort(left: PlatformItem, right: PlatformItem) {
  const leftSort = metadataNumber(left.metadata?.sort)
  const rightSort = metadataNumber(right.metadata?.sort)
  if (leftSort !== rightSort) return leftSort - rightSort
  const leftType = left.type || left.protocol || ''
  const rightType = right.type || right.protocol || ''
  if (leftType !== rightType) return leftType.localeCompare(rightType, undefined, { numeric: true, sensitivity: 'base' })
  return left.name.localeCompare(right.name, undefined, { numeric: true, sensitivity: 'base' })
}

function assetGroupParentName(item: PlatformItem, groups: PlatformItem[]) {
  if (!item.parent_id) return '-'
  const parentKey = assetGroupKey(item.parent_id)
  return groups.find((group) => assetGroupKey(group.id) === parentKey || assetGroupKey(group.name) === parentKey)?.name || item.parent_id
}

function assetGroupAssetCount(group: PlatformItem, assets: PlatformItem[]) {
  return assetGroupAssetIDs(group, assets).size
}

function assetGroupAssetIDs(group: PlatformItem, assets: PlatformItem[]) {
  const keys = new Set([assetGroupKey(group.id), assetGroupKey(group.name)].filter(Boolean))
  return new Set(assets.filter((asset) => assetMatchesGroupKey(asset, keys)).map((asset) => asset.id))
}

function assetMatchesGroupKey(asset: PlatformItem, keys: Set<string>) {
  const candidates = [
    asset.group,
    asset.parent_id,
    metadataText(asset.metadata?.group_id),
    metadataText(asset.metadata?.asset_group_id),
  ].filter((candidate): candidate is string => Boolean(candidate))
  if (candidates.some((candidate) => keys.has(assetGroupKey(candidate)))) return true
  return [
    ...stringArrayValue(asset.metadata?.group_ids),
    ...stringArrayValue(asset.metadata?.asset_group_ids),
  ].some((candidate) => keys.has(assetGroupKey(candidate)))
}

function assetGroupPathText(item: PlatformItem) {
  return metadataText(item.metadata?.path) || metadataText(item.metadata?.full_path)
}

function assetGroupKey(value: unknown) {
  return metadataText(value).trim().toLowerCase()
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

function scheduledTaskScheduleText(item: PlatformItem) {
  const intervalMs = metadataText(item.metadata?.interval_ms)
  if (intervalMs) return `every ${intervalMs} ms`
  const intervalSeconds = metadataText(item.metadata?.interval_seconds)
  if (intervalSeconds) return `every ${intervalSeconds} s`
  const intervalMinutes = metadataText(item.metadata?.interval_minutes)
  if (intervalMinutes) return `every ${intervalMinutes} min`
  const interval = metadataText(item.metadata?.interval) || metadataText(item.metadata?.run_every)
  if (interval) return `every ${interval}`
  const cron = metadataText(item.metadata?.cron) || metadataText(item.metadata?.cron_expression)
  if (cron) return `cron ${cron}`
  if (metadataBool(item.metadata?.run_on_start)) return 'run on start'
  return '-'
}

function stringArrayValue(value: unknown) {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : []
}

function metadataInlineListText(value: unknown) {
  const array = stringArrayValue(value)
  if (array.length) return array.join(', ')
  const text = metadataText(value)
  return text ? splitWords(text).join(', ') : ''
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

function metadataListInputText(metadata: string, key: string) {
  const value = metadataObject(metadata)[key]
  const array = stringArrayValue(value)
  if (array.length) return array.join(' ')
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

function metadataWithWebAssetCertificate(metadata: string, value: string) {
  const next = metadataObject(metadata)
  for (const key of ['certificate_id', 'mtls_certificate_id', 'client_certificate_id', 'cert_id']) {
    delete next[key]
  }
  if (value.trim()) next.certificate_id = value.trim()
  return JSON.stringify(next, null, 2)
}

function metadataWithWebAssetCredentialClear(metadata: string, clear: boolean) {
  const next = metadataObject(metadata)
  if (clear) {
    next.web_upstream_credentials_clear = true
  } else {
    delete next.web_upstream_credentials_clear
    delete next.clear_upstream_credentials
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

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {}
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

function resolveStoragePath(base: string, value: string) {
  const input = value.trim().replace(/\\/g, '/')
  if (!input || input === '.') return joinStoragePath(base, '')
  if (input === '/') return '.'
  if (input.startsWith('/')) return input.replace(/^\/+/, '') || '.'
  return joinStoragePath(base, input)
}

function rootStoragePath(value: string) {
  const clean = value.trim().replace(/\\/g, '/').replace(/^\/+/, '')
  return clean && clean !== '.' ? `/${clean}` : '/'
}

function siblingStoragePath(path: string, nextName: string) {
  const parent = parentStoragePath(path)
  return joinStoragePath(parent, nextName)
}

function copiedStorageName(name: string, isDirectory: boolean) {
  if (isDirectory) return `${name}-copy`
  const dotIndex = name.lastIndexOf('.')
  if (dotIndex <= 0) return `${name}-copy`
  return `${name.slice(0, dotIndex)}-copy${name.slice(dotIndex)}`
}

function renamedStorageName(name: string, isDirectory: boolean) {
  if (isDirectory) return `${name}-renamed`
  const dotIndex = name.lastIndexOf('.')
  if (dotIndex <= 0) return `${name}-renamed`
  return `${name.slice(0, dotIndex)}-renamed${name.slice(dotIndex)}`
}

function sortStorageEntries(entries: StorageEntry[]) {
  return [...entries].sort((left, right) => {
    if (left.is_dir !== right.is_dir) return left.is_dir ? -1 : 1
    return left.name.localeCompare(right.name, undefined, { numeric: true, sensitivity: 'base' })
  })
}

function parentStoragePath(value: string) {
  const parts = value.split('/').filter(Boolean)
  if (parts.length <= 1) return '.'
  return parts.slice(0, -1).join('/')
}

async function downloadResponse(path: string, filename: string) {
  const response = await fetch(path, { credentials: 'same-origin' })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string; setup_required?: boolean }
    throw new ApiError(payload.error || response.statusText, response.status, Boolean(payload.setup_required), payload)
  }
  downloadBlob(filename, await response.blob())
}

async function fetchStorageText(path: string) {
  const response = await fetch(path, { credentials: 'same-origin' })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string; setup_required?: boolean }
    throw new ApiError(payload.error || response.statusText, response.status, Boolean(payload.setup_required), payload)
  }
  return response.text()
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
  if (['active', 'enabled', 'success', 'normal', 'encrypted', 'approved', 'executed'].includes(value)) return 'success' as const
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
