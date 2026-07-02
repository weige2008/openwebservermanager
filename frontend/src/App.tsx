import {
  Activity,
  ArrowRight,
  Bell,
  Clipboard,
  Database,
  Download,
  FileClock,
  HardDrive,
  Home,
  KeyRound,
  ListChecks,
  LogOut,
  Moon,
  MonitorUp,
  Plus,
  Power,
  RefreshCw,
  Search,
  Server as ServerIcon,
  Settings,
  ShieldCheck,
  Sun,
  TerminalSquare,
  Upload,
  UserCircle,
  X,
} from 'lucide-react'
import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'

declare global {
  interface Window {
    Guacamole?: any
  }
}

type AppRoute = 'home' | 'login' | 'app'
type ViewKey = 'overview' | 'servers' | 'credentials' | 'sessions' | 'audit'
type Protocol = 'ssh' | 'rdp'
type Theme = 'light' | 'dark'

type ServerOS = 'linux' | 'windows'
type CredentialType = 'ssh_password' | 'ssh_key' | 'rdp_password'
type SessionStatus = 'pending' | 'active' | 'closed' | 'failed' | string

interface AuthUser {
  id: string
  username: string
  role: string
  expires_at: string
}

interface ManagedServer {
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

interface Credential {
  id: string
  name: string
  type: CredentialType
  username: string
  domain?: string
  created_at: string
  updated_at: string
}

interface ConnectionSession {
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
  started_at: string
  ended_at?: string
  last_activity_at: string
}

interface AuditLog {
  id: string
  user_id: string
  action: string
  target_id: string
  protocol?: Protocol
  detail?: string
  client_ip?: string
  created_at: string
}

interface BootstrapData {
  servers: ManagedServer[]
  credentials: Credential[]
  sessions: ConnectionSession[]
  audit_logs: AuditLog[]
  guacd?: { address: string }
}

type ModalState =
  | { type: 'server' }
  | { type: 'credential' }
  | { type: 'connect'; protocol: Protocol; serverId: string }
  | null

type WorkspaceState =
  | { type: 'ssh'; session: ConnectionSession; status: string }
  | { type: 'rdp'; session: ConnectionSession; status: string }
  | null

class ApiError extends Error {
  setupRequired: boolean
  status: number

  constructor(message: string, status: number, setupRequired = false) {
    super(message)
    this.status = status
    this.setupRequired = setupRequired
  }
}

const decoder = new TextDecoder()
const encoder = new TextEncoder()

function routeFromLocation(): AppRoute {
  const path = window.location.pathname.replace(/\/+$/, '') || '/'
  if (path === '/login' || path === '/sign-in') return 'login'
  if (path === '/app' || path === '/dashboard') return 'app'
  return 'home'
}

function cx(...items: Array<string | false | null | undefined>): string {
  return items.filter(Boolean).join(' ')
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body !== undefined && !headers.has('content-type')) {
    headers.set('content-type', 'application/json')
  }

  const response = await fetch(path, {
    credentials: 'same-origin',
    ...options,
    headers,
  })
  const payload = await response.json().catch(() => ({}))

  if (!response.ok) {
    throw new ApiError(
      payload.error || response.statusText,
      response.status,
      Boolean(payload.setup_required)
    )
  }
  return payload as T
}

function textToBase64(value: string): string {
  let binary = ''
  for (const byte of encoder.encode(value)) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function base64ToText(value?: string): string {
  const binary = atob(value || '')
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return decoder.decode(bytes, { stream: true })
}

function formatDate(value?: string): string {
  if (!value) return '-'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return '-'
  return date.toLocaleString('zh-CN', { hour12: false })
}

function osLabel(value?: string): string {
  if (value === 'windows') return 'Windows'
  if (value === 'linux') return 'Linux'
  return value || '-'
}

function credentialLabel(value: CredentialType): string {
  return {
    ssh_password: 'SSH 密码',
    ssh_key: 'SSH 私钥',
    rdp_password: 'RDP 密码',
  }[value]
}

function statusLabel(value: SessionStatus): string {
  return {
    pending: '等待中',
    active: '活跃',
    closed: '已关闭',
    failed: '失败',
  }[value] || value
}

function Button({
  children,
  variant = 'default',
  size = 'default',
  className,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'primary' | 'ghost' | 'outline' | 'danger'
  size?: 'default' | 'sm' | 'icon'
}) {
  return (
    <button
      className={cx(
        'inline-flex items-center justify-center gap-2 rounded-lg text-sm font-medium transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[color-mix(in_oklch,var(--foreground)_16%,transparent)] disabled:pointer-events-none disabled:opacity-55',
        size === 'default' && 'h-9 px-3.5',
        size === 'sm' && 'h-8 px-2.5 text-xs',
        size === 'icon' && 'size-9 px-0',
        variant === 'default' && 'border border-[var(--border)] bg-[var(--card)] text-[var(--foreground)] hover:bg-[var(--muted)]',
        variant === 'primary' && 'border border-[var(--primary)] bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-90',
        variant === 'outline' && 'border border-[var(--border)] bg-[color-mix(in_oklch,var(--card)_82%,transparent)] text-[var(--foreground)] hover:bg-[var(--muted)]',
        variant === 'ghost' && 'border border-transparent bg-transparent text-[var(--muted-foreground)] hover:bg-[var(--muted)] hover:text-[var(--foreground)]',
        variant === 'danger' && 'border border-[var(--destructive)] bg-[var(--destructive)] text-white hover:opacity-90',
        className
      )}
      {...props}
    >
      {children}
    </button>
  )
}

function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <section className={cx('overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--card)] shadow-[var(--shadow-xs)]', className)}>
      {children}
    </section>
  )
}

function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info' }) {
  return (
    <span
      className={cx(
        'inline-flex h-6 items-center rounded-full border px-2.5 text-xs font-medium whitespace-nowrap',
        tone === 'neutral' && 'border-[var(--border)] bg-[var(--muted)] text-[var(--foreground)]',
        tone === 'success' && 'border-[color-mix(in_oklch,var(--success)_32%,var(--border))] bg-[color-mix(in_oklch,var(--success)_14%,transparent)] text-[var(--foreground)]',
        tone === 'warning' && 'border-[color-mix(in_oklch,var(--warning)_34%,var(--border))] bg-[color-mix(in_oklch,var(--warning)_16%,transparent)] text-[var(--foreground)]',
        tone === 'danger' && 'border-[color-mix(in_oklch,var(--destructive)_35%,var(--border))] bg-[color-mix(in_oklch,var(--destructive)_14%,transparent)] text-[var(--foreground)]',
        tone === 'info' && 'border-[color-mix(in_oklch,var(--info)_32%,var(--border))] bg-[color-mix(in_oklch,var(--info)_14%,transparent)] text-[var(--foreground)]'
      )}
    >
      {children}
    </span>
  )
}

function Field({
  label,
  children,
  className,
}: {
  label: string
  children: ReactNode
  className?: string
}) {
  return (
    <label className={cx('grid gap-1.5 text-sm font-medium', className)}>
      <span>{label}</span>
      {children}
    </label>
  )
}

function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cx(
        'h-10 w-full rounded-lg border border-[var(--input)] bg-[var(--background)] px-3 text-sm text-[var(--foreground)] outline-none transition focus:border-[color-mix(in_oklch,var(--foreground)_35%,var(--border))] focus:ring-3 focus:ring-[color-mix(in_oklch,var(--foreground)_8%,transparent)]',
        props.className
      )}
      {...props}
    />
  )
}

function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cx(
        'h-10 w-full rounded-lg border border-[var(--input)] bg-[var(--background)] px-3 text-sm text-[var(--foreground)] outline-none transition focus:border-[color-mix(in_oklch,var(--foreground)_35%,var(--border))] focus:ring-3 focus:ring-[color-mix(in_oklch,var(--foreground)_8%,transparent)]',
        props.className
      )}
      {...props}
    />
  )
}

function Textarea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cx(
        'min-h-28 w-full resize-y rounded-lg border border-[var(--input)] bg-[var(--background)] px-3 py-2 text-sm text-[var(--foreground)] outline-none transition focus:border-[color-mix(in_oklch,var(--foreground)_35%,var(--border))] focus:ring-3 focus:ring-[color-mix(in_oklch,var(--foreground)_8%,transparent)]',
        props.className
      )}
      {...props}
    />
  )
}

function EmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="grid min-h-40 place-items-center gap-2 px-6 py-8 text-center">
      <strong>{title}</strong>
      <p className="max-w-md text-sm text-[var(--muted-foreground)]">{body}</p>
    </div>
  )
}

function Brand({ className }: { className?: string }) {
  return (
    <div className={cx('inline-flex items-center gap-2.5', className)}>
      <span className="size-7 rounded-[10px] bg-[linear-gradient(135deg,color-mix(in_oklch,var(--info)_82%,white),color-mix(in_oklch,var(--success)_76%,black))] shadow-[inset_0_0_0_1px_rgb(255_255_255_/_0.24)]" />
      <span className="text-sm font-semibold tracking-tight">ServerManager</span>
    </div>
  )
}

function Toast({ message }: { message: string }) {
  if (!message) return null
  return (
    <div className="fixed right-4 bottom-4 z-70 max-w-[calc(100vw-2rem)] rounded-xl border border-[var(--border)] bg-[var(--popover)] px-4 py-3 text-sm text-[var(--popover-foreground)] shadow-[var(--shadow-card)]">
      {message}
    </div>
  )
}

export default function App() {
  const [route, setRoute] = useState<AppRoute>(routeFromLocation)
  const [booted, setBooted] = useState(false)
  const [setupRequired, setSetupRequired] = useState(false)
  const [auth, setAuth] = useState<AuthUser | null>(null)
  const [view, setView] = useState<ViewKey>(() => (localStorage.getItem('servermanager:view') as ViewKey) || 'overview')
  const [theme, setTheme] = useState<Theme>(() => (localStorage.getItem('servermanager:theme') as Theme) || 'light')
  const [data, setData] = useState<BootstrapData>({ servers: [], credentials: [], sessions: [], audit_logs: [] })
  const [modal, setModal] = useState<ModalState>(null)
  const [workspace, setWorkspace] = useState<WorkspaceState>(null)
  const [toast, setToast] = useState('')

  const showToast = useCallback((message: string) => {
    setToast(message)
    window.setTimeout(() => setToast(''), 3600)
  }, [])

  const clearPrivateState = useCallback(() => {
    setData({ servers: [], credentials: [], sessions: [], audit_logs: [] })
    setWorkspace(null)
  }, [])

  const navigate = useCallback((path: string) => {
    window.history.pushState({}, '', path)
    setRoute(routeFromLocation())
  }, [])

  const refresh = useCallback(
    async (silent = false) => {
      const next = await request<BootstrapData>('/api/bootstrap')
      setData({
        servers: next.servers || [],
        credentials: next.credentials || [],
        sessions: next.sessions || [],
        audit_logs: next.audit_logs || [],
        guacd: next.guacd,
      })
      if (!silent) showToast('数据已刷新')
    },
    [showToast]
  )

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('servermanager:theme', theme)
  }, [theme])

  useEffect(() => {
    const onPopState = () => setRoute(routeFromLocation())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  useEffect(() => {
    const bootstrap = async () => {
      try {
        const status = await request<{ configured: boolean }>('/api/auth/status')
        setSetupRequired(!status.configured)
        if (status.configured) {
          const me = await request<{ user: AuthUser }>('/api/auth/me')
          setAuth(me.user)
          await refresh(true)
        } else {
          clearPrivateState()
        }
      } catch {
        clearPrivateState()
      } finally {
        setBooted(true)
      }
    }
    void bootstrap()
  }, [clearPrivateState, refresh])

  const setActiveView = (next: ViewKey) => {
    setView(next)
    localStorage.setItem('servermanager:view', next)
    if (route !== 'app') navigate('/app')
  }

  const handleLogout = async () => {
    try {
      await request('/api/auth/logout', { method: 'POST', body: '{}' })
    } catch {
      // Local state should clear even when the server session has already expired.
    }
    setAuth(null)
    clearPrivateState()
    navigate('/')
  }

  const handleApiError = (error: unknown) => {
    if (error instanceof ApiError && error.setupRequired) {
      setSetupRequired(true)
      setAuth(null)
      clearPrivateState()
      navigate('/login')
    }
    showToast(error instanceof Error ? error.message : '操作失败')
  }

  if (!booted) {
    return (
      <div className="grid min-h-screen place-items-center bg-[var(--background)] text-[var(--foreground)]">
        <div className="grid gap-4 text-center">
          <Brand className="justify-center" />
          <div className="rounded-xl border border-[var(--border)] bg-[var(--card)] px-4 py-3 text-sm text-[var(--muted-foreground)]">
            正在加载控制台...
          </div>
        </div>
      </div>
    )
  }

  const shellProps = {
    auth,
    data,
    view,
    theme,
    route,
    setupRequired,
    setTheme,
    setModal,
    setWorkspace,
    setActiveView,
    navigate,
    refresh,
    handleLogout,
    showToast,
    handleApiError,
    setAuth,
    setSetupRequired,
  }

  return (
    <>
      {workspace ? (
        <WorkspaceView
          workspace={workspace}
          servers={data.servers}
          setWorkspace={setWorkspace}
          refresh={refresh}
          showToast={showToast}
          onCloseSession={async (id) => {
            await request(`/api/connections/${id}/close`, { method: 'POST', body: '{}' })
            await refresh(true)
          }}
        />
      ) : auth ? (
        route === 'home' ? (
          <LandingPage {...shellProps} authenticated />
        ) : (
          <AuthenticatedApp {...shellProps} />
        )
      ) : route === 'login' || route === 'app' ? (
        <AuthPage {...shellProps} />
      ) : (
        <LandingPage {...shellProps} authenticated={false} />
      )}
      {auth && modal ? <ModalHost {...shellProps} modal={modal} /> : null}
      <Toast message={toast} />
    </>
  )
}

interface SharedProps {
  auth: AuthUser | null
  data: BootstrapData
  view: ViewKey
  theme: Theme
  route: AppRoute
  setupRequired: boolean
  setTheme: (theme: Theme) => void
  setModal: (modal: ModalState) => void
  setWorkspace: (workspace: WorkspaceState) => void
  setActiveView: (view: ViewKey) => void
  navigate: (path: string) => void
  refresh: (silent?: boolean) => Promise<void>
  handleLogout: () => Promise<void>
  showToast: (message: string) => void
  handleApiError: (error: unknown) => void
  setAuth: (user: AuthUser | null) => void
  setSetupRequired: (required: boolean) => void
}

function PublicHeader(props: SharedProps & { authenticated: boolean }) {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const authLabel = props.setupRequired ? '初始化' : '登录'

  return (
    <header className="pointer-events-none fixed inset-x-0 top-0 z-50">
      <nav
        className={cx(
          'pointer-events-auto mx-auto flex items-center justify-between transition-all duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]',
          scrolled
            ? 'mt-3 h-12 w-[min(52rem,calc(100%-1.5rem))] rounded-2xl border border-[color-mix(in_oklch,var(--border)_70%,transparent)] bg-[color-mix(in_oklch,var(--background)_72%,transparent)] pr-1.5 pl-4 shadow-[var(--shadow-xs)] backdrop-blur-2xl'
            : 'h-16 w-[min(72rem,calc(100%-2rem))] px-2'
        )}
      >
        <Button variant="ghost" className="px-0 hover:bg-transparent" onClick={() => props.navigate('/')}>
          <Brand />
        </Button>
        <div className="hidden items-center gap-1 sm:flex">
          <a className="rounded-lg px-3 py-1.5 text-[13px] font-medium text-[var(--muted-foreground)] hover:text-[var(--foreground)]" href="#features">
            功能
          </a>
          <a className="rounded-lg px-3 py-1.5 text-[13px] font-medium text-[var(--muted-foreground)] hover:text-[var(--foreground)]" href="#security">
            安全
          </a>
          <a className="rounded-lg px-3 py-1.5 text-[13px] font-medium text-[var(--muted-foreground)] hover:text-[var(--foreground)]" href="#workflow">
            工作区
          </a>
        </div>
        <div className="flex items-center gap-2">
          <Button size="icon" variant="outline" title="切换主题" onClick={() => props.setTheme(props.theme === 'dark' ? 'light' : 'dark')}>
            {props.theme === 'dark' ? <Sun className="size-4" /> : <Moon className="size-4" />}
          </Button>
          <Button variant="primary" onClick={() => props.navigate(props.authenticated ? '/app' : '/login')}>
            {props.authenticated ? '进入控制台' : authLabel}
          </Button>
        </div>
      </nav>
    </header>
  )
}

function LandingPage(props: SharedProps & { authenticated: boolean }) {
  const entryText = props.authenticated ? '进入控制台' : props.setupRequired ? '初始化管理员' : '登录控制台'

  return (
    <div className="min-h-screen overflow-x-clip bg-[var(--background)] text-[var(--foreground)]">
      <PublicHeader {...props} />
      <main>
        <section className="mx-auto grid min-h-[720px] w-[min(72rem,calc(100%-2rem))] grid-cols-1 items-center gap-12 pt-32 pb-14 lg:grid-cols-[minmax(0,1fr)_minmax(420px,0.92fr)]">
          <div className="flex flex-col items-start">
            <div className="landing-animate inline-flex items-center gap-2 rounded-full border border-[color-mix(in_oklch,var(--info)_22%,transparent)] bg-[color-mix(in_oklch,var(--info)_7%,transparent)] px-3 py-1.5 text-[11px] font-medium text-[color-mix(in_oklch,var(--info)_86%,var(--foreground))]">
              <span className="pulse-dot relative size-1.5 rounded-full bg-[var(--info)] before:absolute before:inset-0 before:rounded-full before:bg-[var(--info)]" />
              在线服务器管理第一阶段
            </div>
            <h1 className="landing-animate mt-5 max-w-3xl text-[clamp(2.3rem,5vw,4.6rem)] leading-[1.05] font-bold tracking-tight" style={{ animationDelay: '60ms' }}>
              浏览器里的 SSH 终端与 RDP 桌面
            </h1>
            <p className="landing-animate mt-5 max-w-xl text-base leading-relaxed text-[var(--muted-foreground)]" style={{ animationDelay: '120ms' }}>
              面向 Linux 与 Windows 服务器的统一连接工作台。凭据只在服务端加密保存，浏览器只负责终端、桌面渲染和输入事件。
            </p>
            <div className="landing-animate mt-8 flex flex-wrap items-center gap-3" style={{ animationDelay: '180ms' }}>
              <Button variant="primary" className="h-11 rounded-lg px-5" onClick={() => props.navigate(props.authenticated ? '/app' : '/login')}>
                {entryText}
                <ArrowRight className="size-4" />
              </Button>
              <Button variant="outline" className="h-11 rounded-lg px-5" onClick={() => document.querySelector('#features')?.scrollIntoView({ behavior: 'smooth' })}>
                查看能力
              </Button>
            </div>
            <div className="landing-animate mt-9 flex flex-wrap gap-2" style={{ animationDelay: '240ms' }}>
              {['SSH PTY', 'Guacamole RDP', '录屏审计', '文件传输'].map((item) => (
                <span key={item} className="rounded-full border border-[var(--border)] bg-[color-mix(in_oklch,var(--muted)_55%,transparent)] px-3 py-1.5 text-xs font-semibold">
                  {item}
                </span>
              ))}
            </div>
          </div>
          <HeroDemo />
        </section>

        <section id="features" className="mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-3 md:grid-cols-3">
          <PublicStat title="SSH" body="浏览器 WebSocket 到服务端 SSH PTY，支持密码、私钥与 passphrase。" />
          <PublicStat title="RDP" body="Go tunnel 接入 guacd，前端只渲染桌面与键鼠输入。" />
          <PublicStat title="审计" body="会话、断开、录屏下载与关键操作写入审计日志。" />
        </section>

        <section id="security" className="mx-auto mt-6 grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 items-center gap-8 rounded-2xl border border-[var(--border)] bg-[var(--card)] p-7 shadow-[var(--shadow-xs)] lg:grid-cols-[minmax(0,0.95fr)_minmax(280px,1fr)]">
          <div>
            <div className="text-xs font-medium tracking-[0.12em] text-[var(--muted-foreground)] uppercase">Security Boundary</div>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight">登录后才进入服务器资产区</h2>
            <p className="mt-2 text-sm leading-relaxed text-[var(--muted-foreground)]">
              公开首页不展示服务器列表、凭据、会话或审计日志。所有连接 API、WebSocket 与录屏下载都需要有效管理员会话。
            </p>
          </div>
          <div className="flex flex-wrap gap-2 lg:justify-end">
            {['HttpOnly Cookie 会话', '凭据不下发浏览器', 'AES-GCM 本地加密存储', '连接操作审计'].map((item) => (
              <span key={item} className="rounded-full border border-[var(--border)] bg-[color-mix(in_oklch,var(--muted)_55%,transparent)] px-3 py-1.5 text-xs font-semibold">
                {item}
              </span>
            ))}
          </div>
        </section>

        <section id="workflow" className="mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-3 py-6 pb-12 md:grid-cols-3">
          <WorkflowStep index="1" title="登记服务器" body="记录主机、系统、SSH/RDP 端口与分组。" />
          <WorkflowStep index="2" title="保存凭据" body="密码、私钥、域账号只在后端加密保存。" />
          <WorkflowStep index="3" title="打开工作区" body="SSH 与 RDP 全屏连接，顶部保留状态与断开操作。" />
        </section>
      </main>
    </div>
  )
}

function HeroDemo() {
  return (
    <div className="landing-animate overflow-hidden rounded-[1.35rem] border border-[var(--border)] bg-[var(--card)] shadow-[var(--shadow-card)]" style={{ animationDelay: '300ms' }}>
      <div className="flex h-11 items-center gap-2 border-b border-[var(--border)] px-3">
        <span className="size-2.5 rounded-full bg-[var(--destructive)]" />
        <span className="size-2.5 rounded-full bg-[var(--warning)]" />
        <span className="size-2.5 rounded-full bg-[var(--success)]" />
        <span className="ml-auto font-mono text-xs text-[var(--muted-foreground)]">session://rdp/sess_live</span>
      </div>
      <div className="grid min-h-[430px] grid-cols-[76px_1fr] bg-[radial-gradient(circle_at_70%_12%,color-mix(in_oklch,var(--info)_18%,transparent),transparent_32%),var(--background)] max-sm:grid-cols-1">
        <div className="grid content-start gap-3 border-r border-[var(--border)] p-4 max-sm:hidden">
          {[0, 1, 2, 3].map((i) => (
            <span key={i} className="h-9 rounded-xl bg-[var(--muted)]" />
          ))}
        </div>
        <div className="grid gap-4 p-5">
          <div className="grid min-h-44 content-start gap-2 rounded-2xl bg-[#030305] p-5 font-mono text-xs text-zinc-300 shadow-[inset_0_0_0_1px_rgb(255_255_255_/_0.08)]">
            <code>$ ssh ubuntu@server</code>
            <code>Welcome to Ubuntu 24.04 LTS</code>
            <code>$ systemctl status nginx</code>
            <code className="text-emerald-300">active (running)</code>
          </div>
          <div className="grid min-h-48 grid-cols-[1fr_0.62fr] gap-4">
            <div className="rounded-2xl border border-[var(--border)] bg-[linear-gradient(180deg,color-mix(in_oklch,var(--info)_18%,var(--card)),var(--card))]" />
            <div className="rounded-2xl border border-[var(--border)] bg-[linear-gradient(180deg,color-mix(in_oklch,var(--success)_12%,var(--card)),var(--card))]" />
          </div>
        </div>
      </div>
    </div>
  )
}

function PublicStat({ title, body }: { title: string; body: string }) {
  return (
    <article className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-5 shadow-[var(--shadow-xs)]">
      <span className="text-sm font-semibold">{title}</span>
      <p className="mt-2 text-sm text-[var(--muted-foreground)]">{body}</p>
    </article>
  )
}

function WorkflowStep({ index, title, body }: { index: string; title: string; body: string }) {
  return (
    <article className="rounded-2xl border border-[var(--border)] bg-[var(--card)] p-5 shadow-[var(--shadow-xs)]">
      <span className="mb-3 inline-flex size-8 items-center justify-center rounded-xl border border-[var(--border)] bg-[var(--muted)] font-semibold">{index}</span>
      <strong className="block">{title}</strong>
      <p className="mt-2 text-sm text-[var(--muted-foreground)]">{body}</p>
    </article>
  )
}

function AuthPage(props: SharedProps) {
  const [submitting, setSubmitting] = useState(false)

  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)
    try {
      if (props.setupRequired) {
        const password = String(form.get('password') || '')
        const confirm = String(form.get('confirm_password') || '')
        if (password !== confirm) {
          props.showToast('两次输入的密码不一致')
          return
        }
        const res = await request<{ user: AuthUser }>('/api/auth/setup', {
          method: 'POST',
          body: JSON.stringify({
            username: String(form.get('username') || 'admin'),
            password,
          }),
        })
        props.setSetupRequired(false)
        props.setAuth(res.user)
        await props.refresh(true)
        props.navigate('/app')
        props.showToast('管理员已创建')
      } else {
        const res = await request<{ user: AuthUser }>('/api/auth/login', {
          method: 'POST',
          body: JSON.stringify({
            username: String(form.get('username') || ''),
            password: String(form.get('password') || ''),
          }),
        })
        props.setAuth(res.user)
        await props.refresh(true)
        props.navigate('/app')
        props.showToast('已登录')
      }
    } catch (error) {
      props.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="grid min-h-screen place-items-center bg-[var(--background)] px-4 py-20 text-[var(--foreground)]">
      <Button variant="ghost" className="fixed top-6 left-6 px-0 hover:bg-transparent" onClick={() => props.navigate('/')}>
        <Brand />
      </Button>
      <main className="grid w-full max-w-[480px] gap-8">
        <div className="space-y-2">
          <div className="text-xs font-medium tracking-[0.12em] text-[var(--muted-foreground)] uppercase">{props.setupRequired ? 'First Run' : 'Admin Console'}</div>
          <h1 className="text-3xl font-semibold tracking-tight">{props.setupRequired ? '首次设置管理员' : '登录'}</h1>
          <p className="text-sm leading-relaxed text-[var(--muted-foreground)]">
            {props.setupRequired ? '当前数据库还没有管理员账号。创建后才能查看服务器、凭据、会话与审计数据。' : '登录后查看服务器列表、凭据、连接会话与审计记录。'}
          </p>
        </div>
        <form className="grid gap-4" onSubmit={onSubmit}>
          <Field label="用户名">
            <Input name="username" autoComplete="username" placeholder="admin" defaultValue={props.setupRequired ? 'admin' : ''} required />
          </Field>
          <Field label={props.setupRequired ? '新密码' : '密码'}>
            <Input name="password" type="password" autoComplete={props.setupRequired ? 'new-password' : 'current-password'} placeholder={props.setupRequired ? '至少 8 位' : '请输入管理员密码'} minLength={props.setupRequired ? 8 : undefined} required />
          </Field>
          {props.setupRequired ? (
            <Field label="确认密码">
              <Input name="confirm_password" type="password" autoComplete="new-password" placeholder="再次输入新密码" minLength={8} required />
            </Field>
          ) : null}
          <Button variant="primary" className="w-full" disabled={submitting}>
            {props.setupRequired ? '创建管理员并进入控制台' : '登录控制台'}
          </Button>
        </form>
        <p className="text-center text-xs text-[var(--muted-foreground)]">
          {props.setupRequired ? '密码只会以 bcrypt 哈希形式写入服务端数据库，不会以明文保存。' : '管理员密码保存在服务端数据库中，浏览器只保存 HttpOnly 会话 Cookie。'}
        </p>
      </main>
    </div>
  )
}

function AuthenticatedApp(props: SharedProps) {
  return (
    <div className="grid min-h-screen grid-cols-[258px_minmax(0,1fr)] bg-[var(--background)] text-[var(--foreground)] max-md:grid-cols-1">
      <Sidebar {...props} />
      <main className="grid min-w-0 grid-rows-[64px_minmax(0,1fr)] max-md:grid-rows-[auto_minmax(0,1fr)]">
        <AppHeader {...props} />
        <section className="grid content-start gap-4 p-4 md:p-5">
          {props.view === 'servers' ? <ServersView {...props} /> : null}
          {props.view === 'credentials' ? <CredentialsView {...props} /> : null}
          {props.view === 'sessions' ? <SessionsView {...props} /> : null}
          {props.view === 'audit' ? <AuditView {...props} /> : null}
          {props.view === 'overview' ? <OverviewView {...props} /> : null}
        </section>
      </main>
    </div>
  )
}

function Sidebar(props: SharedProps) {
  const nav = [
    { key: 'overview' as const, label: '总览', icon: Home },
    { key: 'servers' as const, label: '服务器', icon: ServerIcon },
    { key: 'credentials' as const, label: '凭据', icon: KeyRound },
    { key: 'sessions' as const, label: '会话', icon: MonitorUp },
    { key: 'audit' as const, label: '审计', icon: FileClock },
  ]
  return (
    <aside className="sticky top-0 grid h-screen grid-rows-[auto_1fr_auto] gap-4 border-r border-[var(--border)] bg-[var(--sidebar)] p-3 max-md:relative max-md:h-auto max-md:border-r-0 max-md:border-b">
      <Button variant="ghost" className="justify-start px-2 hover:bg-transparent" onClick={() => props.navigate('/')}>
        <Brand />
      </Button>
      <nav className="grid content-start gap-1 max-md:grid-cols-5 max-md:overflow-auto">
        {nav.map((item) => {
          const Icon = item.icon
          return (
            <Button
              key={item.key}
              variant={props.view === item.key ? 'outline' : 'ghost'}
              className={cx('justify-start max-md:justify-center', props.view === item.key && 'bg-[var(--card)] shadow-[var(--shadow-xs)]')}
              onClick={() => props.setActiveView(item.key)}
            >
              <span className="flex size-7 items-center justify-center rounded-lg bg-[var(--muted)]">
                <Icon className="size-3.5" />
              </span>
              <span className="max-md:hidden">{item.label}</span>
            </Button>
          )
        })}
      </nav>
      <div className="grid gap-1 rounded-2xl border border-[var(--border)] bg-[color-mix(in_oklch,var(--card)_70%,transparent)] p-3 text-sm">
        <span className="text-xs text-[var(--muted-foreground)]">guacd</span>
        <strong className="break-all">{props.data.guacd?.address || '未连接'}</strong>
      </div>
    </aside>
  )
}

function AppHeader(props: SharedProps) {
  const title = viewTitle(props.view)
  return (
    <header className="sticky top-0 z-20 flex items-center justify-between gap-4 border-b border-[var(--border)] bg-[color-mix(in_oklch,var(--background)_82%,transparent)] px-5 backdrop-blur-xl max-md:relative max-md:flex-col max-md:items-start max-md:p-4">
      <div>
        <div className="text-xs text-[var(--muted-foreground)]">ServerManager / {title}</div>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">{title}</h1>
      </div>
      <div className="flex flex-wrap items-center justify-end gap-2 max-md:grid max-md:w-full max-md:grid-cols-2">
        <Button variant="outline" onClick={() => void props.refresh()}>
          <RefreshCw className="size-4" />
          刷新
        </Button>
        <Button variant="outline" onClick={() => props.setModal({ type: 'credential' })}>
          <KeyRound className="size-4" />
          添加凭据
        </Button>
        <Button variant="primary" onClick={() => props.setModal({ type: 'server' })}>
          <Plus className="size-4" />
          添加服务器
        </Button>
        <Button size="icon" variant="outline" onClick={() => props.setTheme(props.theme === 'dark' ? 'light' : 'dark')} title="切换主题">
          {props.theme === 'dark' ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </Button>
        <Button variant="outline" onClick={() => void props.handleLogout()} className="max-md:col-span-2">
          <UserCircle className="size-4" />
          {props.auth?.username || 'admin'}
          <LogOut className="size-4" />
        </Button>
      </div>
    </header>
  )
}

function viewTitle(view: ViewKey): string {
  return {
    overview: '总览',
    servers: '服务器',
    credentials: '凭据',
    sessions: '连接会话',
    audit: '审计日志',
  }[view]
}

function OverviewView(props: SharedProps) {
  const active = props.data.sessions.filter((item) => item.status === 'active').length
  const recordings = props.data.sessions.filter((item) => item.recording_path).length
  return (
    <>
      <section className="rounded-2xl border border-[var(--border)] bg-[radial-gradient(circle_at_80%_0%,color-mix(in_oklch,var(--info)_12%,transparent),transparent_34%),var(--card)] p-5 shadow-[var(--shadow-xs)]">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="text-xs font-medium tracking-[0.12em] text-[var(--muted-foreground)] uppercase">Connection Workspace</div>
            <h2 className="mt-2 text-2xl font-semibold tracking-tight">从服务器资产直接进入 SSH 或 RDP</h2>
            <p className="mt-1 max-w-2xl text-sm text-[var(--muted-foreground)]">第一阶段专注在线连接：登记服务器和凭据后，在服务器列表里打开全屏终端或桌面工作区。</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => props.setActiveView('credentials')}>管理凭据</Button>
            <Button variant="primary" onClick={() => props.setActiveView('servers')}>打开服务器列表</Button>
          </div>
        </div>
      </section>
      <section className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={ServerIcon} title="服务器" value={props.data.servers.length} desc="已登记 Linux / Windows 主机" />
        <StatCard icon={KeyRound} title="凭据" value={props.data.credentials.length} desc="SSH 密码、私钥与 RDP 账号" />
        <StatCard icon={Activity} title="活跃会话" value={active} desc="当前仍在运行的连接" />
        <StatCard icon={Database} title="录屏索引" value={recordings} desc="RDP 原始录屏目录" />
      </section>
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,0.8fr)]">
        <Card>
          <PanelHeader title="最近会话" action={<Button variant="ghost" onClick={() => props.setActiveView('sessions')}>查看全部</Button>} />
          <SessionsTable sessions={props.data.sessions.slice(-6).reverse()} servers={props.data.servers} onClose={async (id) => {
            await request(`/api/connections/${id}/close`, { method: 'POST', body: '{}' })
            await props.refresh(true)
          }} />
        </Card>
        <Card>
          <PanelHeader title="快速服务器" action={<Button variant="ghost" onClick={() => props.setActiveView('servers')}>管理</Button>} />
          {props.data.servers.length ? (
            <div className="grid">
              {props.data.servers.slice(0, 6).map((server) => (
                <div key={server.id} className="flex items-center justify-between gap-3 border-b border-[var(--border)] px-4 py-3 last:border-b-0">
                  <span className="min-w-0">
                    <strong className="block truncate">{server.name}</strong>
                    <em className="block truncate text-xs not-italic text-[var(--muted-foreground)]">{server.host}</em>
                  </span>
                  <span className="flex gap-2">
                    <Button size="sm" variant="primary" onClick={() => props.setModal({ type: 'connect', protocol: 'ssh', serverId: server.id })}>SSH</Button>
                    <Button size="sm" onClick={() => props.setModal({ type: 'connect', protocol: 'rdp', serverId: server.id })}>RDP</Button>
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState title="还没有服务器" body="添加第一台服务器后，可以在这里快速发起连接。" />
          )}
        </Card>
      </section>
    </>
  )
}

function StatCard({ icon: Icon, title, value, desc }: { icon: typeof ServerIcon; title: string; value: number; desc: string }) {
  return (
    <Card className="p-4">
      <div className="flex items-center justify-between gap-3 text-xs font-medium text-[var(--muted-foreground)]">
        <span>{title}</span>
        <span className="flex size-8 items-center justify-center rounded-lg bg-[var(--muted)] text-[var(--foreground)]">
          <Icon className="size-4" />
        </span>
      </div>
      <strong className="mt-3 block text-3xl leading-none">{value}</strong>
      <p className="mt-2 text-xs text-[var(--muted-foreground)]">{desc}</p>
    </Card>
  )
}

function PanelHeader({ title, desc, action }: { title: string; desc?: string; action?: ReactNode }) {
  return (
    <div className="flex min-h-14 items-center justify-between gap-3 border-b border-[var(--border)] px-4 py-3">
      <div>
        <h2 className="text-base font-semibold">{title}</h2>
        {desc ? <p className="mt-0.5 text-xs text-[var(--muted-foreground)]">{desc}</p> : null}
      </div>
      {action}
    </div>
  )
}

function ServersView(props: SharedProps) {
  return (
    <Card>
      <PanelHeader title="服务器资产" desc="登录后可见，连接动作会写入审计日志。" action={<Button variant="primary" onClick={() => props.setModal({ type: 'server' })}><Plus className="size-4" />添加服务器</Button>} />
      {props.data.servers.length ? (
        <div className="overflow-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-[color-mix(in_oklch,var(--foreground)_1.5%,var(--background))] text-left text-xs text-[var(--muted-foreground)]">
                <th className="px-3 py-3 font-semibold">名称</th>
                <th className="px-3 py-3 font-semibold">地址</th>
                <th className="px-3 py-3 font-semibold">系统</th>
                <th className="px-3 py-3 font-semibold">端口</th>
                <th className="px-3 py-3 font-semibold">分组</th>
                <th className="px-3 py-3" />
              </tr>
            </thead>
            <tbody>
              {props.data.servers.map((server) => (
                <tr key={server.id} className="table-row-animate border-b border-[var(--border)] last:border-b-0 hover:bg-[color-mix(in_oklch,var(--foreground)_2.6%,transparent)]">
                  <td className="px-3 py-3 align-middle">
                    <strong>{server.name}</strong>
                    <div className="text-xs text-[var(--muted-foreground)]">{server.description || '无描述'}</div>
                  </td>
                  <td className="px-3 py-3 align-middle font-mono text-xs">{server.host}</td>
                  <td className="px-3 py-3 align-middle"><Badge tone={server.os === 'windows' ? 'info' : 'neutral'}>{osLabel(server.os)}</Badge></td>
                  <td className="px-3 py-3 align-middle">SSH {server.ssh_port || 22} / RDP {server.rdp_port || 3389}</td>
                  <td className="px-3 py-3 align-middle">{server.group || '-'}</td>
                  <td className="px-3 py-3 align-middle">
                    <div className="flex justify-end gap-2">
                      <Button size="sm" variant="primary" onClick={() => props.setModal({ type: 'connect', protocol: 'ssh', serverId: server.id })}>SSH</Button>
                      <Button size="sm" onClick={() => props.setModal({ type: 'connect', protocol: 'rdp', serverId: server.id })}>RDP</Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title="还没有服务器" body="添加服务器后，SSH/RDP 入口会出现在列表右侧。" />
      )}
    </Card>
  )
}

function CredentialsView(props: SharedProps) {
  return (
    <Card>
      <PanelHeader title="凭据库" desc="敏感字段加密保存在服务端，API 响应不会返回明文。" action={<Button variant="primary" onClick={() => props.setModal({ type: 'credential' })}><Plus className="size-4" />添加凭据</Button>} />
      {props.data.credentials.length ? (
        <div className="overflow-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-[color-mix(in_oklch,var(--foreground)_1.5%,var(--background))] text-left text-xs text-[var(--muted-foreground)]">
                <th className="px-3 py-3 font-semibold">名称</th>
                <th className="px-3 py-3 font-semibold">类型</th>
                <th className="px-3 py-3 font-semibold">用户名</th>
                <th className="px-3 py-3 font-semibold">域 / 工作组</th>
                <th className="px-3 py-3 font-semibold">创建时间</th>
              </tr>
            </thead>
            <tbody>
              {props.data.credentials.map((credential) => (
                <tr key={credential.id} className="table-row-animate border-b border-[var(--border)] last:border-b-0 hover:bg-[color-mix(in_oklch,var(--foreground)_2.6%,transparent)]">
                  <td className="px-3 py-3"><strong>{credential.name}</strong></td>
                  <td className="px-3 py-3"><Badge>{credentialLabel(credential.type)}</Badge></td>
                  <td className="px-3 py-3">{credential.username}</td>
                  <td className="px-3 py-3">{credential.domain || '-'}</td>
                  <td className="px-3 py-3">{formatDate(credential.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title="还没有凭据" body="添加 SSH 或 RDP 凭据后才能发起连接。" />
      )}
    </Card>
  )
}

function SessionsView(props: SharedProps) {
  return (
    <Card>
      <PanelHeader title="连接会话" desc="包含协议、目标服务器、状态、来源 IP 与录屏索引。" />
      <SessionsTable sessions={[...props.data.sessions].reverse()} servers={props.data.servers} onClose={async (id) => {
        await request(`/api/connections/${id}/close`, { method: 'POST', body: '{}' })
        await props.refresh(true)
      }} />
    </Card>
  )
}

function SessionsTable({ sessions, servers, onClose }: { sessions: ConnectionSession[]; servers: ManagedServer[]; onClose: (id: string) => Promise<void> }) {
  if (!sessions.length) return <EmptyState title="暂无连接会话" body="从服务器列表发起 SSH 或 RDP 后会出现在这里。" />
  const serverName = (id: string) => servers.find((server) => server.id === id)?.name || id
  return (
    <div className="overflow-auto">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="bg-[color-mix(in_oklch,var(--foreground)_1.5%,var(--background))] text-left text-xs text-[var(--muted-foreground)]">
            <th className="px-3 py-3 font-semibold">协议</th>
            <th className="px-3 py-3 font-semibold">服务器</th>
            <th className="px-3 py-3 font-semibold">状态</th>
            <th className="px-3 py-3 font-semibold">来源</th>
            <th className="px-3 py-3 font-semibold">开始时间</th>
            <th className="px-3 py-3 font-semibold">录屏</th>
            <th className="px-3 py-3" />
          </tr>
        </thead>
        <tbody>
          {sessions.map((session) => (
            <tr key={session.id} className="table-row-animate border-b border-[var(--border)] last:border-b-0 hover:bg-[color-mix(in_oklch,var(--foreground)_2.6%,transparent)]">
              <td className="px-3 py-3"><Badge tone={session.protocol === 'rdp' ? 'info' : 'neutral'}>{session.protocol.toUpperCase()}</Badge></td>
              <td className="px-3 py-3"><strong>{serverName(session.server_id)}</strong><div className="font-mono text-xs text-[var(--muted-foreground)]">{session.id}</div></td>
              <td className="px-3 py-3"><Badge tone={session.status === 'active' ? 'success' : session.status === 'pending' ? 'warning' : session.status === 'failed' ? 'danger' : 'neutral'}>{statusLabel(session.status)}</Badge></td>
              <td className="px-3 py-3">{session.client_ip || '-'}</td>
              <td className="px-3 py-3">{formatDate(session.started_at)}</td>
              <td className="px-3 py-3">{session.recording_path ? `${session.recording_size || 0} bytes` : '-'}</td>
              <td className="px-3 py-3">
                <div className="flex justify-end gap-2">
                  {session.recording_path ? (
                    <Button size="sm" onClick={() => { window.location.href = `/api/connections/${session.id}/recording.zip` }}>
                      <Download className="size-3.5" />
                      下载录屏
                    </Button>
                  ) : null}
                  <Button size="sm" onClick={() => void onClose(session.id)}>关闭</Button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AuditView(props: SharedProps) {
  return (
    <Card>
      <PanelHeader title="审计日志" desc="连接、断开、凭据创建、录屏访问都会记录。" />
      {props.data.audit_logs.length ? (
        <div className="overflow-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="bg-[color-mix(in_oklch,var(--foreground)_1.5%,var(--background))] text-left text-xs text-[var(--muted-foreground)]">
                <th className="px-3 py-3 font-semibold">时间</th>
                <th className="px-3 py-3 font-semibold">动作</th>
                <th className="px-3 py-3 font-semibold">目标</th>
                <th className="px-3 py-3 font-semibold">协议</th>
                <th className="px-3 py-3 font-semibold">来源</th>
                <th className="px-3 py-3 font-semibold">详情</th>
              </tr>
            </thead>
            <tbody>
              {[...props.data.audit_logs].reverse().map((log) => (
                <tr key={log.id} className="table-row-animate border-b border-[var(--border)] last:border-b-0 hover:bg-[color-mix(in_oklch,var(--foreground)_2.6%,transparent)]">
                  <td className="px-3 py-3">{formatDate(log.created_at)}</td>
                  <td className="px-3 py-3 font-mono text-xs">{log.action}</td>
                  <td className="px-3 py-3">{log.target_id || '-'}</td>
                  <td className="px-3 py-3">{log.protocol || '-'}</td>
                  <td className="px-3 py-3">{log.client_ip || '-'}</td>
                  <td className="px-3 py-3">{log.detail || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState title="暂无审计日志" body="登录与连接操作会逐步写入这里。" />
      )}
    </Card>
  )
}

function ModalHost(props: SharedProps & { modal: Exclude<ModalState, null> }) {
  if (props.modal.type === 'server') return <ServerModal {...props} />
  if (props.modal.type === 'credential') return <CredentialModal {...props} />
  return <ConnectModal {...props} modal={props.modal} />
}

function ModalShell({ title, desc, children, onClose, compact }: { title: string; desc?: string; children: ReactNode; onClose: () => void; compact?: boolean }) {
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-black/50 p-4" onMouseDown={(event) => {
      if (event.target === event.currentTarget) onClose()
    }}>
      <section className={cx('grid max-h-[calc(100vh-2rem)] w-full grid-rows-[auto_minmax(0,1fr)] overflow-hidden rounded-2xl border border-[var(--border)] bg-[var(--card)] shadow-[var(--shadow-card)]', compact ? 'max-w-xl' : 'max-w-3xl')}>
        <header className="flex items-start justify-between gap-4 border-b border-[var(--border)] p-4">
          <div>
            <h2 className="text-lg font-semibold">{title}</h2>
            {desc ? <p className="mt-1 text-sm text-[var(--muted-foreground)]">{desc}</p> : null}
          </div>
          <Button size="icon" variant="ghost" onClick={onClose}><X className="size-4" /></Button>
        </header>
        <div className="overflow-auto p-4">{children}</div>
      </section>
    </div>
  )
}

function ServerModal(props: SharedProps) {
  const [submitting, setSubmitting] = useState(false)
  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)
    try {
      await request('/api/servers', {
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
      props.setModal(null)
      await props.refresh(true)
      props.showToast('服务器已添加')
    } catch (error) {
      props.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }
  return (
    <ModalShell title="添加服务器" desc="保存主机基础信息后即可绑定凭据发起连接。" onClose={() => props.setModal(null)}>
      <form className="grid grid-cols-1 gap-3 md:grid-cols-2" onSubmit={onSubmit}>
        <Field label="名称"><Input name="name" placeholder="生产网关" required /></Field>
        <Field label="主机地址"><Input name="host" placeholder="10.0.0.12 / example.com" required /></Field>
        <Field label="系统"><Select name="os" defaultValue="linux"><option value="linux">Linux</option><option value="windows">Windows</option></Select></Field>
        <Field label="分组"><Input name="group" placeholder="default" /></Field>
        <Field label="SSH 端口"><Input name="ssh_port" type="number" defaultValue={22} /></Field>
        <Field label="RDP 端口"><Input name="rdp_port" type="number" defaultValue={3389} /></Field>
        <Field label="描述" className="md:col-span-2"><Textarea name="description" placeholder="用途、环境、负责人等" /></Field>
        <div className="flex justify-end gap-2 md:col-span-2">
          <Button type="button" variant="outline" onClick={() => props.setModal(null)}>取消</Button>
          <Button variant="primary" disabled={submitting}>保存服务器</Button>
        </div>
      </form>
    </ModalShell>
  )
}

function CredentialModal(props: SharedProps) {
  const [submitting, setSubmitting] = useState(false)
  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setSubmitting(true)
    const form = new FormData(event.currentTarget)
    try {
      await request('/api/credentials', {
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
      props.setModal(null)
      await props.refresh(true)
      props.showToast('凭据已添加')
    } catch (error) {
      props.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }
  return (
    <ModalShell title="添加凭据" desc="明文只在提交时发送一次，服务端加密落盘。" onClose={() => props.setModal(null)}>
      <form className="grid grid-cols-1 gap-3 md:grid-cols-2" onSubmit={onSubmit}>
        <Field label="名称"><Input name="name" placeholder="root-key / windows-admin" required /></Field>
        <Field label="类型"><Select name="type" defaultValue="ssh_password"><option value="ssh_password">SSH 密码</option><option value="ssh_key">SSH 私钥</option><option value="rdp_password">RDP 密码</option></Select></Field>
        <Field label="用户名"><Input name="username" placeholder="root / ubuntu / Administrator" required /></Field>
        <Field label="域 / 工作组"><Input name="domain" placeholder="可选" /></Field>
        <Field label="密码"><Input name="password" type="password" placeholder="可选" /></Field>
        <Field label="私钥 passphrase"><Input name="passphrase" type="password" placeholder="可选" /></Field>
        <Field label="私钥" className="md:col-span-2"><Textarea name="private_key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" /></Field>
        <div className="flex justify-end gap-2 md:col-span-2">
          <Button type="button" variant="outline" onClick={() => props.setModal(null)}>取消</Button>
          <Button variant="primary" disabled={submitting}>保存凭据</Button>
        </div>
      </form>
    </ModalShell>
  )
}

function ConnectModal(props: SharedProps & { modal: { type: 'connect'; protocol: Protocol; serverId: string } }) {
  const server = props.data.servers.find((item) => item.id === props.modal.serverId)
  const credentials = props.data.credentials.filter((credential) =>
    props.modal.protocol === 'ssh'
      ? credential.type === 'ssh_password' || credential.type === 'ssh_key'
      : credential.type === 'rdp_password'
  )
  const [submitting, setSubmitting] = useState(false)
  const onSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setSubmitting(true)
    try {
      const credentialId = String(form.get('credential_id') || '')
      if (props.modal.protocol === 'ssh') {
        const session = await request<ConnectionSession>('/api/connections/ssh', {
          method: 'POST',
          body: JSON.stringify({ server_id: props.modal.serverId, credential_id: credentialId, cols: 120, rows: 32, term: 'xterm-256color' }),
        })
        props.setModal(null)
        props.setWorkspace({ type: 'ssh', session, status: 'connecting' })
      } else {
        const session = await request<ConnectionSession>('/api/connections/rdp', {
          method: 'POST',
          body: JSON.stringify({
            server_id: props.modal.serverId,
            credential_id: credentialId,
            width: Math.max(1024, window.innerWidth),
            height: Math.max(680, window.innerHeight - 52),
            dpi: 96,
          }),
        })
        props.setModal(null)
        props.setWorkspace({ type: 'rdp', session, status: 'connecting' })
      }
    } catch (error) {
      props.handleApiError(error)
    } finally {
      setSubmitting(false)
    }
  }
  return (
    <ModalShell compact title={`连接到 ${server?.name || '服务器'}`} desc={`${props.modal.protocol.toUpperCase()} 会话将以全屏工作区打开。`} onClose={() => props.setModal(null)}>
      {credentials.length ? (
        <form className="grid gap-4" onSubmit={onSubmit}>
          <Field label="凭据">
            <Select name="credential_id">
              {credentials.map((credential) => <option key={credential.id} value={credential.id}>{credential.name} ({credential.username})</option>)}
            </Select>
          </Field>
          <div className="flex flex-wrap gap-2">
            <Badge>{server?.host || '-'}</Badge>
            <Badge>{props.modal.protocol === 'ssh' ? `SSH ${server?.ssh_port || 22}` : `RDP ${server?.rdp_port || 3389}`}</Badge>
            <Badge>{props.modal.protocol === 'rdp' ? '启用录屏目录' : 'PTY 终端'}</Badge>
          </div>
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" onClick={() => props.setModal(null)}>取消</Button>
            <Button variant="primary" disabled={submitting}>开始连接</Button>
          </div>
        </form>
      ) : (
        <div className="grid gap-4">
          <EmptyState title={`没有可用的 ${props.modal.protocol.toUpperCase()} 凭据`} body="请先创建对应类型的凭据，再发起连接。" />
          <div className="flex justify-end">
            <Button variant="primary" onClick={() => props.setModal({ type: 'credential' })}>添加凭据</Button>
          </div>
        </div>
      )}
    </ModalShell>
  )
}

function WorkspaceView({
  workspace,
  servers,
  setWorkspace,
  refresh,
  showToast,
  onCloseSession,
}: {
  workspace: Exclude<WorkspaceState, null>
  servers: ManagedServer[]
  setWorkspace: (workspace: WorkspaceState) => void
  refresh: (silent?: boolean) => Promise<void>
  showToast: (message: string) => void
  onCloseSession: (id: string) => Promise<void>
}) {
  const [status, setStatus] = useState(workspace.status)
  const server = servers.find((item) => item.id === workspace.session.server_id)

  const leave = async () => {
    setWorkspace(null)
    await refresh(true)
  }

  const close = async () => {
    await onCloseSession(workspace.session.id)
    setWorkspace(null)
    await refresh(true)
  }

  return (
    <div className="grid min-h-screen grid-rows-[52px_minmax(0,1fr)] bg-[#050506] text-zinc-100">
      <div className="flex min-w-0 items-center justify-between gap-3 border-b border-white/10 bg-[#0d0d10] px-3 max-md:h-auto max-md:flex-col max-md:items-start max-md:py-3">
        <div className="flex min-w-0 items-center gap-2">
          <strong>{workspace.session.protocol.toUpperCase()}</strong>
          <span className="truncate text-zinc-400">{server?.name || workspace.session.server_id}</span>
          <Badge tone={status === 'connected' ? 'success' : 'neutral'}>{status}</Badge>
          {workspace.session.protocol === 'rdp' ? <Badge tone="danger">录屏中</Badge> : null}
        </div>
        <div className="flex flex-wrap gap-2">
          {workspace.type === 'rdp' ? (
            <>
              <Button variant="outline" onClick={() => window.dispatchEvent(new Event('servermanager:rdp-clipboard'))}><Clipboard className="size-4" />剪贴板</Button>
              <Button variant="outline" onClick={() => window.dispatchEvent(new Event('servermanager:rdp-upload'))}><Upload className="size-4" />上传文件</Button>
            </>
          ) : null}
          <Button variant="outline" onClick={() => void leave()}>返回控制台</Button>
          <Button variant="danger" onClick={() => void close()}><Power className="size-4" />断开</Button>
        </div>
      </div>
      {workspace.type === 'ssh' ? (
        <SSHWorkspace session={workspace.session} setStatus={setStatus} />
      ) : (
        <RDPWorkspace session={workspace.session} setStatus={setStatus} showToast={showToast} />
      )}
    </div>
  )
}

function SSHWorkspace({ session, setStatus }: { session: ConnectionSession; setStatus: (status: string) => void }) {
  const containerRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!containerRef.current) return
    const term = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: 'Cascadia Mono, JetBrains Mono, Consolas, monospace',
      fontSize: 13,
      theme: { background: '#030305', foreground: '#d4d4d8' },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)
    fit.fit()
    term.focus()
    term.write('Connecting...\r\n')

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const socket = new WebSocket(`${proto}://${window.location.host}/api/connections/ssh/${session.id}/ws?cols=${term.cols}&rows=${term.rows}&term=xterm-256color`)
    const sendResize = () => {
      fit.fit()
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
      }
    }
    const resizeObserver = new ResizeObserver(sendResize)
    resizeObserver.observe(containerRef.current)

    term.onData((data) => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'stdin', data: textToBase64(data) }))
      }
    })

    socket.onopen = () => sendResize()
    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'ready') {
        setStatus('connected')
        term.write('Connected.\r\n')
      }
      if (msg.type === 'stdout' || msg.type === 'stderr') term.write(base64ToText(msg.data).replaceAll('\n', '\r\n'))
      if (msg.type === 'error') term.write(`\r\n[error] ${msg.data}\r\n`)
    }
    socket.onclose = () => {
      setStatus('disconnected')
      term.write('\r\n[disconnected]\r\n')
    }

    return () => {
      resizeObserver.disconnect()
      socket.close()
      term.dispose()
    }
  }, [session.id, setStatus])

  return <div ref={containerRef} className="h-[calc(100vh-52px)] bg-[#030305] p-3 max-md:h-[calc(100vh-120px)]" />
}

function RDPWorkspace({ session, setStatus, showToast }: { session: ConnectionSession; setStatus: (status: string) => void; showToast: (message: string) => void }) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const clientRef = useRef<any>(null)

  useEffect(() => {
    const container = containerRef.current
    const Guacamole = window.Guacamole
    if (!container) return
    if (!Guacamole) {
      container.innerHTML = '<div style="margin:20px;padding:16px;border:1px solid rgba(255,255,255,.12);border-radius:14px;background:#111113">缺少 /vendor/guacamole-common.min.js，请放置 guacamole-common-js 后重新连接。</div>'
      return
    }

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const width = Math.max(1024, window.innerWidth)
    const height = Math.max(680, window.innerHeight - 52)
    const tunnel = new Guacamole.WebSocketTunnel(`${proto}://${window.location.host}/api/connections/rdp/${session.id}/tunnel?width=${width}&height=${height}&dpi=96`)
    const client = new Guacamole.Client(tunnel)
    clientRef.current = client
    container.appendChild(client.getDisplay().getElement())
    client.connect('')

    const mouse = new Guacamole.Mouse(client.getDisplay().getElement())
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = (mouseState: unknown) => client.sendMouseState(mouseState)
    const keyboard = new Guacamole.Keyboard(document)
    keyboard.onkeydown = (keysym: number) => client.sendKeyEvent(1, keysym)
    keyboard.onkeyup = (keysym: number) => client.sendKeyEvent(0, keysym)
    client.onstatechange = (stateCode: number) => {
      if (stateCode === 3) setStatus('connected')
      if (stateCode === 5) setStatus('disconnected')
    }
    client.onerror = (err: { message?: string }) => showToast(err.message || 'RDP 连接失败')

    const onClipboard = () => {
      const text = window.prompt('发送到远程剪贴板')
      if (text == null) return
      const stream = client.createClipboardStream('text/plain')
      const writer = new Guacamole.StringWriter(stream)
      writer.sendText(text)
      writer.sendEnd()
      showToast('剪贴板已发送')
    }
    const onUpload = () => {
      const input = document.createElement('input')
      input.type = 'file'
      input.onchange = () => {
        const file = input.files?.[0]
        if (!file) return
        const stream = client.createFileStream(file.type || 'application/octet-stream', file.name)
        const writer = new Guacamole.BlobWriter(stream)
        writer.oncomplete = () => showToast('文件已发送')
        writer.sendBlob(file)
        writer.sendEnd()
      }
      input.click()
    }
    const onResize = () => {
      if (typeof client.sendSize === 'function') client.sendSize(window.innerWidth, window.innerHeight - 52)
    }
    const onBeforeUnload = () => client.disconnect()
    window.addEventListener('servermanager:rdp-clipboard', onClipboard)
    window.addEventListener('servermanager:rdp-upload', onUpload)
    window.addEventListener('resize', onResize)
    window.addEventListener('beforeunload', onBeforeUnload)

    return () => {
      window.removeEventListener('servermanager:rdp-clipboard', onClipboard)
      window.removeEventListener('servermanager:rdp-upload', onUpload)
      window.removeEventListener('resize', onResize)
      window.removeEventListener('beforeunload', onBeforeUnload)
      client.disconnect()
      clientRef.current = null
      container.innerHTML = ''
    }
  }, [session.id, setStatus, showToast])

  return <div ref={containerRef} className="h-[calc(100vh-52px)] overflow-hidden bg-[#020204] max-md:h-[calc(100vh-120px)]" />
}
