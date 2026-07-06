export type AppRoute = 'home' | 'login' | 'console'
export type ConsoleView = 'overview' | 'servers' | 'sessions' | 'audit'
export type Protocol = 'ssh' | 'rdp' | 'vnc' | 'http' | 'database'
export type Theme = 'light' | 'dark' | 'system'
export type ResolvedTheme = 'light' | 'dark'
export type Locale = 'zh' | 'en' | 'zh-TW' | 'fr' | 'ru' | 'ja' | 'vi'
export type ThemePreset =
  | 'default'
  | 'anthropic'
  | 'simple-large'
  | 'underground'
  | 'rose-garden'
  | 'lake-view'
  | 'sunset-glow'
  | 'forest-whisper'
  | 'ocean-breeze'
  | 'lavender-dream'
export type ThemeFont = 'default' | 'sans' | 'serif'
export type ThemeRadius = 'default' | 'none' | 'sm' | 'md' | 'lg' | 'xl'
export type ThemeScale = 'default' | 'sm' | 'lg' | 'xl'
export type ThemeContentLayout = 'full' | 'centered'
export type ThemeSidebarStyle = 'default' | 'inset' | 'floating'
export type ServerOS = 'linux' | 'windows'
export type CredentialType = 'ssh_password' | 'ssh_key' | 'rdp_password' | 'vnc_password' | 'database_password'
export type SessionStatus = 'pending' | 'active' | 'closed' | 'failed' | string

export interface AuthUser {
  id: string
  username: string
  role: string
  expires_at: string
  api_permissions?: string[]
  menu_permissions?: string[]
}

export interface ManagedServer {
  id: string
  name: string
  host: string
  ssh_port?: number
  rdp_port?: number
  os: ServerOS
  group?: string
  description?: string
  created_at: string
  updated_at: string
}

export interface Credential {
  id: string
  server_id?: string
  name: string
  type: CredentialType
  username: string
  domain?: string
  created_at: string
  updated_at: string
}

export interface ConnectionSession {
  id: string
  protocol: Protocol
  server_id: string
  credential_id: string
  user_id: string
  status: SessionStatus
  client_ip?: string
  error?: string
  recording_path?: string
  recording_size?: number
  width?: number
  height?: number
  dpi?: number
  color_depth?: number
  resize_method?: string
  clipboard_enabled?: boolean
  file_transfer_enabled?: boolean
  ignore_cert?: boolean
  read_only?: boolean
  watermark_enabled?: boolean
  watermark_text?: string
  watermark_color?: string
  watermark_font_size?: number
  started_at: string
  ended_at?: string
  last_activity_at: string
}

export interface AuditLog {
  id: string
  user_id: string
  action: string
  target_id: string
  protocol?: Protocol
  detail?: string
  client_ip?: string
  created_at: string
}

export interface PlatformItem {
  id: string
  module: string
  name: string
  type?: string
  status?: string
  protocol?: Protocol
  host?: string
  port?: number
  username?: string
  group?: string
  owner_id?: string
  parent_id?: string
  target_id?: string
  tags?: string[]
  permissions?: Record<string, boolean>
  description?: string
  metadata?: Record<string, unknown>
  created_at: string
  updated_at: string
}

export type PlatformData = Record<string, PlatformItem[]>

export interface BootstrapData {
  servers: ManagedServer[]
  credentials: Credential[]
  sessions: ConnectionSession[]
  audit_logs: AuditLog[]
  platform?: PlatformData
  guacd?: { address: string }
}

export interface PublicNavLink {
  title: string
  href: string
  external?: boolean
}

export interface PublicConfig {
  site_name: string
  version?: string
  commit?: string
  github_url?: string
  copyright?: string
  logo_url?: string
  asset_logo_url?: string
  icp_number?: string
  about_title?: string
  about_description?: string
  about_body?: string
  footer_text?: string
  nav_links: PublicNavLink[]
}

export interface ThemeAppearance {
  preset: ThemePreset
  font: ThemeFont
  radius: ThemeRadius
  scale: ThemeScale
  contentLayout: ThemeContentLayout
  sidebarStyle: ThemeSidebarStyle
}

export type ModalState =
  | { type: 'server' }
  | { type: 'credential'; serverId: string }
  | { type: 'connect'; protocol: Protocol; serverId: string }
  | null

export type WorkspaceState =
  | { type: 'ssh'; session: ConnectionSession; status: string }
  | { type: 'rdp'; session: ConnectionSession; status: string }
  | { type: 'vnc'; session: ConnectionSession; status: string }
  | null

export interface ApiErrorPayload {
  error?: string
  setup_required?: boolean
  mfa_required?: boolean
  mfa_scope?: string
  mfa_setup_required?: boolean
  expires_in?: number
}
