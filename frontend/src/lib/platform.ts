import {
  Activity,
  Archive,
  BadgeCheck,
  BookText,
  Boxes,
  BriefcaseBusiness,
  CalendarClock,
  ClipboardList,
  Clock3,
  Code2,
  Database,
  FileClock,
  FileKey2,
  FileText,
  Fingerprint,
  Gauge,
  Globe2,
  HardDrive,
  KeyRound,
  Landmark,
  ListChecks,
  LockKeyhole,
  Network,
  RadioTower,
  ScrollText,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  SquareTerminal,
  Users,
  type LucideIcon,
} from 'lucide-react'

export interface PlatformPageConfig {
  route: string
  collection: string
  labelZh: string
  labelEn: string
  descriptionZh: string
  descriptionEn: string
  icon: LucideIcon
  apiPath?: string
  kind?: 'table' | 'settings' | 'monitor' | 'tools' | 'access' | 'backups'
}

export interface PlatformNavGroup {
  labelZh: string
  labelEn: string
  icon: LucideIcon
  items: PlatformPageConfig[]
}

const resourceItems: PlatformPageConfig[] = [
  page('/app/assets', 'assets', '资产', 'Assets', '统一管理 SSH/RDP/VNC 资产，支持分组、标签、状态、导入导出和批量授权。', 'Manage SSH/RDP/VNC assets with groups, tags, status, import/export, and authorization.', Server, '/api/admin/assets'),
  page('/app/database-assets', 'database_assets', '数据库资产', 'Database assets', '管理 MySQL/PostgreSQL 等数据库资产和代理接入信息。', 'Manage database assets and database proxy metadata.', Database, '/api/admin/database-assets'),
  page('/app/credentials', 'credentials', '授权凭证', 'Credentials', '独立凭据库，敏感字段服务端加密保存。', 'Credential vault with server-side encrypted secrets.', KeyRound, '/api/admin/credentials'),
  page('/app/command-snippets', 'command_snippets', '命令片段', 'Command snippets', '维护公开或私有命令片段，供 SSH 终端快速插入。', 'Manage public or private command snippets for SSH terminals.', Code2, '/api/admin/command-snippets'),
  page('/app/storages', 'storages', '存储', 'Storage', '用户文件盘、共享开关、容量限制和文件系统入口。', 'User drives, sharing, quotas, and filesystem entry points.', HardDrive, '/api/admin/storages'),
  page('/app/web-assets', 'web_assets', 'Web资产', 'Web assets', 'Web 资产域名、目标地址、启用状态和反向代理入口。', 'Web asset domains, upstreams, status, and reverse proxy entry points.', Globe2, '/api/admin/websites'),
  page('/app/certificates', 'certificates', '证书管理', 'Certificates', '自签、上传、ACME、DNS 供应商、mTLS 和默认证书管理。', 'Self-signed, uploaded, ACME, DNS provider, mTLS, and default certificate management.', FileKey2, '/api/admin/certificates'),
  page('/app/sql-work-orders', 'sql_work_orders', 'SQL 工单', 'SQL work orders', 'SQL 申请、审批、执行原因、影响行数和执行时间。', 'SQL requests, approvals, reasons, affected rows, and execution time.', ClipboardList, '/api/admin/sql-work-orders'),
]

const gatewayItems: PlatformPageConfig[] = [
  page('/app/ssh-gateways', 'ssh_gateways', 'SSH网关', 'SSH gateways', '原生 SSH 客户端接入、资产选择、直连资产和端口转发白名单。', 'Native SSH client gateway, asset selection, direct connect, and forwarding allowlist.', SquareTerminal, '/api/admin/ssh-gateways'),
  page('/app/agent-gateways', 'agent_gateways', '安全网关', 'Secure gateways', 'Agent 注册、通信令牌、延迟、负载和资源指标。', 'Agent registration, tokens, latency, load, and resource metrics.', RadioTower, '/api/admin/agent-gateways'),
  page('/app/gateway-groups', 'gateway_groups', '网关分组', 'Gateway groups', '手动或自动选择网关成员，用于资产接入路由。', 'Manual or automatic gateway member selection for asset routing.', Network, '/api/admin/gateway-groups'),
]

const auditItems: PlatformPageConfig[] = [
  page('/app/online-sessions', 'online_sessions', '在线会话', 'Online sessions', '查看活跃会话并支持强制断开。', 'View active sessions and force disconnect.', Activity, '/api/admin/audit/online-sessions'),
  page('/app/offline-sessions', 'offline_sessions', '离线会话', 'Offline sessions', '查看录屏大小、审计状态、转码、回放、下载和删除入口。', 'View recording size, audit state, transcoding, playback, download, and deletion.', FileClock, '/api/admin/audit/offline-sessions'),
  page('/app/exec-command-logs', 'exec_command_logs', '远程命令记录', 'Remote command logs', '记录 SSH exec 非交互命令、结果、退出码、耗时和风险等级。', 'Record SSH exec commands, result, exit code, duration, and risk level.', SquareTerminal, '/api/admin/audit/exec-command-logs'),
  page('/app/file-logs', 'file_logs', '文件日志', 'File logs', '记录上传、下载、删除、重命名等文件操作。', 'Record file upload, download, delete, and rename operations.', FileText, '/api/admin/audit/file-logs'),
  page('/app/access-logs', 'access_logs', '访问日志', 'Access logs', '记录 Web 资产请求方法、URI、状态码、IP、耗时和 User-Agent。', 'Record Web asset method, URI, status, IP, latency, and User-Agent.', ScrollText, '/api/admin/audit/access-logs'),
  page('/app/access-stats', 'access_stats', '访问日志统计', 'Access stats', 'PV、UV、独立 IP、流量、错误率、热门页面和来源统计。', 'PV, UV, unique IPs, traffic, error rate, top pages, and referrers.', Gauge, '/api/admin/audit/access-stats'),
  page('/app/login-logs', 'login_logs', '登录日志', 'Login logs', '账号、客户端 IP、登录状态、失败原因、客户端和登录时间。', 'Account, client IP, status, failure reason, client, and login time.', LockKeyhole, '/api/admin/audit/login-logs'),
  page('/app/operation-logs', 'operation_logs', '操作日志', 'Operation logs', '账户、模块、资源、操作类型、状态、请求和客户端。', 'Account, module, resource, action, status, request, and client.', ListChecks, '/api/admin/audit/operation-logs'),
  page('/app/sql-logs', 'sql_logs', 'SQL 日志', 'SQL logs', '数据库资产、用户、来源、状态、耗时、影响行数和 SQL。', 'Database asset, user, source, status, duration, affected rows, and SQL.', Database, '/api/admin/audit/sql-logs'),
]

const opsItems: PlatformPageConfig[] = [
  page('/app/scheduled-tasks', 'scheduled_tasks', '定时任务', 'Scheduled tasks', '证书续签、日志清理、资产状态检查和备份任务。', 'Certificate renewal, log cleanup, asset checks, and backup jobs.', CalendarClock, '/api/admin/scheduled-tasks'),
  { ...page('/app/backups', 'backups', '备份恢复', 'Backup and restore', '查看、下载、立即创建备份，并上传备份恢复系统数据。', 'View, download, create, and restore system backups.', Archive, '/api/admin/backups'), kind: 'backups' },
  { ...page('/app/tools', 'tools', '实用工具', 'Tools', 'Ping 与 TCP Ping 检测工具。', 'Ping and TCP Ping diagnostics.', Gauge, '/api/tools/ping'), kind: 'tools' },
  { ...page('/app/monitoring', 'system_monitoring', '系统监控', 'Monitoring', '集中查看服务、网关、会话、存储和告警运行状态。', 'Centralized service, gateway, session, storage, and alert status.', Activity, '/api/system/monitoring'), kind: 'monitor' },
]

const identityItems: PlatformPageConfig[] = [
  page('/app/users', 'users', '用户', 'Users', '用户列表、新建、编辑、删除、启用禁用、导入和登录状态。', 'Users, create/edit/delete, enable/disable, import, and login status.', Users, '/api/admin/users'),
  page('/app/roles', 'roles', '角色', 'Roles', 'Built-in and custom roles with menu/API permissions.', '内置与自定义角色、菜单/API 权限。', BadgeCheck, '/api/admin/roles'),
  page('/app/departments', 'departments', '部门', 'Departments', '表格/树形视图、上级部门、排序和成员数量。', 'Table/tree view, parent department, order, and member count.', Landmark, '/api/admin/departments'),
  page('/app/login-policies', 'login_policies', '登录策略', 'Login policies', 'IP 组、优先级、动作、状态和失效时间。', 'IP groups, priority, action, status, and expiry.', Shield, '/api/admin/login-policies'),
  page('/app/login-locked', 'login_locks', '登录锁定', 'Login locks', 'IP、账号、锁定类型、锁定时间和失效时间。', 'IP, account, lock type, lock time, and expiry.', LockKeyhole, '/api/admin/login-locked'),
  page('/app/oidc-clients', 'oidc_clients', 'OIDC 客户端', 'OIDC clients', 'Client ID、回调地址、授权类型、Scopes、状态和描述。', 'Client ID, redirect URI, grant types, scopes, status, and description.', Fingerprint, '/api/admin/oidc-clients'),
]

const authzItems: PlatformPageConfig[] = [
  page('/app/command-filters', 'command_filters', '命令拦截器', 'Command filters', '命令匹配、风险等级和允许/拒绝/审批动作。', 'Command matching, risk level, and allow/deny/approval action.', ShieldCheck, '/api/admin/command-filters'),
  page('/app/authorization-strategies', 'authorization_strategies', '授权策略', 'Authorization strategies', '上传、下载、编辑、删除、重命名、复制和粘贴权限矩阵。', 'Upload, download, edit, delete, rename, copy, and paste permission matrix.', BookText, '/api/admin/strategies'),
  page('/app/authorized-assets', 'authorized_assets', '授权资产', 'Authorized assets', '按用户、部门、资产组和资产授权，支持失效时间。', 'Authorize by user, department, asset group, and asset with expiry.', Server, '/api/admin/authorizations/assets'),
  page('/app/authorized-web-assets', 'authorized_web_assets', '授权Web资产', 'Authorized Web assets', '按用户、部门、Web 资产组和 Web 资产授权。', 'Authorize Web assets by user, department, and group.', Globe2, '/api/admin/authorizations/websites'),
  page('/app/authorized-database-assets', 'authorized_database_assets', '授权数据库资产', 'Authorized database assets', '按用户、部门和数据库资产授权。', 'Authorize database assets by user and department.', Database, '/api/admin/authorizations/databases'),
]

const settingsItems: PlatformPageConfig[] = [
  { ...page('/app/system-settings', 'system_settings', '系统设置', 'System settings', '品牌、接入、水印、MFA、代理、通知、日志保留、备份和关于。', 'Branding, access, watermark, MFA, proxy, notification, retention, backup, and about.', Settings, '/api/admin/system-settings'), kind: 'settings' },
]

export const platformNavGroups: PlatformNavGroup[] = [
  { labelZh: '资源管理', labelEn: 'Resources', icon: Boxes, items: resourceItems },
  { labelZh: '接入网关', labelEn: 'Gateways', icon: RadioTower, items: gatewayItems },
  { labelZh: '日志审计', labelEn: 'Audit', icon: FileClock, items: auditItems },
  { labelZh: '系统运维', labelEn: 'Operations', icon: BriefcaseBusiness, items: opsItems },
  { labelZh: '身份认证', labelEn: 'Identity', icon: Users, items: identityItems },
  { labelZh: '资源授权', labelEn: 'Authorization', icon: ShieldCheck, items: authzItems },
  { labelZh: '系统设置', labelEn: 'Settings', icon: Settings, items: settingsItems },
]

export const platformPages = platformNavGroups.flatMap((group) => group.items)

export function platformPageByRoute(route: string) {
  return platformPages.find((item) => item.route === route)
}

export function platformLabel(config: Pick<PlatformPageConfig, 'labelZh' | 'labelEn'>, locale: string) {
  return locale.startsWith('zh') ? config.labelZh : config.labelEn
}

function page(
  route: string,
  collection: string,
  labelZh: string,
  labelEn: string,
  descriptionZh: string,
  descriptionEn: string,
  icon: LucideIcon,
  apiPath?: string
): PlatformPageConfig {
  return { route, collection, labelZh, labelEn, descriptionZh, descriptionEn, icon, apiPath }
}

export function platformDescription(config: PlatformPageConfig, locale: string) {
  return locale.startsWith('zh') ? config.descriptionZh : config.descriptionEn
}

export const platformHomeStats = [
  { key: 'users', labelZh: '用户', labelEn: 'Users', icon: Users },
  { key: 'assets', labelZh: '资产', labelEn: 'Assets', icon: Server },
  { key: 'web_assets', labelZh: 'Web资产', labelEn: 'Web assets', icon: Globe2 },
  { key: 'database_assets', labelZh: '数据库资产', labelEn: 'Database assets', icon: Database },
  { key: 'online_sessions', labelZh: '在线会话', labelEn: 'Online sessions', icon: Activity },
  { key: 'offline_sessions', labelZh: '离线会话', labelEn: 'Offline sessions', icon: Archive },
  { key: 'operation_logs', labelZh: '操作日志', labelEn: 'Operation logs', icon: FileClock },
  { key: 'scheduled_tasks', labelZh: '定时任务', labelEn: 'Scheduled tasks', icon: Clock3 },
]
