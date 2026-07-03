import { Link } from '@tanstack/react-router'
import {
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  CloudCog,
  DatabaseZap,
  Download,
  FileUp,
  KeyRound,
  LockKeyhole,
  MonitorUp,
  Network,
  RadioTower,
  Server,
  ShieldCheck,
  TerminalSquare,
  type LucideIcon,
} from 'lucide-react'

import { useApp } from '@/app/app-provider'
import { PublicHeader } from '@/components/layout/public-header'
import { Button, buttonVariants } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { cn } from '@/lib/utils'

const homeCopy = {
  'zh-CN': {
    badge: '面向团队的自托管服务器连接工作台',
    heroBody:
      '在浏览器里统一打开 SSH 终端与 RDP 桌面。服务器资产、连接凭据、会话录屏和审计日志集中管理，适合部署在 Linux、Windows 与内网测试环境中。',
    viewProduct: '查看产品能力',
    highlights: ['自托管部署', '浏览器直连', '凭据加密', '会话审计'],
    productTitle: '把分散的远程连接收进同一个控制台',
    productBody:
      'ServerManager 的公开页只展示产品信息；登录后才进入服务器列表、凭据管理和连接工作区。首阶段聚焦在线 SSH 与 RDP，让日常登录、排障、文件流转和审计留痕更顺手。',
    capabilities: [
      ['统一资产入口', '按系统类型、主机地址和连接端口登记服务器，为 SSH/RDP 会话提供清晰入口。'],
      ['内置轻量数据层', '服务器、凭据、会话和审计记录本地保存，默认即可在单机测试环境运行。'],
      ['实时连接状态', '连接创建、打开、断开和错误状态回写会话记录，便于追踪现场。'],
      ['跨平台部署目标', 'Go 后端与前端静态资源一体发布，Linux 和 Windows 部署路径保持一致。'],
    ],
    connectionsTitle: '终端、桌面、传输与录屏，集中在工作区完成',
    connectionsBody:
      '连接工作区以可用性优先：主区域留给终端和桌面，顶部保留状态、剪贴板、文件传输、录屏状态和断开操作。',
    openWorkspace: '打开工作区',
    connectionCards: [
      ['SSH 在线终端', '基于 WebSocket 与 SSH PTY 的实时终端，支持密码、私钥和 passphrase，窗口尺寸随浏览器同步。'],
      ['RDP 远程桌面', '通过 Guacamole tunnel 接入 Windows 桌面，支持键鼠输入、剪贴板、分辨率自适应与文件传输。'],
      ['录屏与审计', '会话创建、连接、断开、录屏下载等关键动作进入审计链路，RDP 原始录屏本地留存。'],
    ],
    securityTitle: '公开展示和真实资产之间保持明确边界',
    securityBody:
      '首页是对外入口，控制台才是运维工作区。敏感资产、凭据和会话数据不在公开页面输出，连接通道也不会把真实凭据交给浏览器。',
    securityItems: [
      ['凭据不进入浏览器', 'SSH 密码、私钥和 RDP 账号仅在服务端解密使用，前端只处理终端输出、桌面画面和输入事件。'],
      ['本地加密存储', '凭据由服务端主密钥保护，数据库只保存密文和必要索引，便于在单机或内网环境落地。'],
      ['登录后访问资源', '公开首页不暴露服务器列表、凭据、连接会话或审计日志，所有工作区 API 均需要有效会话。'],
    ],
    workflowTitle: '从登记主机到断开留痕，只保留必要步骤',
    workflowBody:
      '第一阶段不扩展完整监控、告警和批量任务，把连接闭环先做稳：资产、凭据、会话、录屏和审计各自清楚。',
    workflowSteps: [
      ['01', '登记服务器', '录入 Linux / Windows 主机、连接端口、系统类型和分组信息。'],
      ['02', '保存凭据', '创建 SSH 或 RDP 凭据，敏感字段只在后端加密保存。'],
      ['03', '发起连接', '在服务器详情中打开 SSH 终端或 RDP 桌面，进入全屏工作区。'],
      ['04', '留存审计', '会话状态、断开原因、录屏文件和关键操作可追溯。'],
    ],
    deployTitle: '部署形态',
    deployBody: '默认监听 23876，可通过环境变量覆盖。',
    footerBody: '自托管的在线服务器连接工作台，把 SSH、RDP、凭据、录屏和审计放在同一套访问边界内。',
    footerBuilt: 'Built for browser-based SSH and RDP access.',
    footerProduct: '产品',
    footerLinks: ['产品能力', '连接工作区', '安全边界', '部署形态'],
  },
  'en-US': {
    badge: 'Self-hosted server connection workspace for teams',
    heroBody:
      'Open SSH terminals and RDP desktops directly in the browser. Server inventory, credentials, recordings, and audit logs stay centralized for Linux, Windows, and private test environments.',
    viewProduct: 'View capabilities',
    highlights: ['Self-hosted', 'Browser access', 'Encrypted secrets', 'Session audit'],
    productTitle: 'Bring scattered remote access into one console',
    productBody:
      'The public page presents product information only. After sign-in, operators can manage servers, credentials, and connection workspaces. Phase one focuses on online SSH and RDP for daily access, troubleshooting, file movement, and audit trails.',
    capabilities: [
      ['Unified assets', 'Register Linux and Windows servers by system type, host, and connection port.'],
      ['Lightweight data layer', 'Servers, credentials, sessions, and audit logs are stored locally for simple single-node testing.'],
      ['Live connection state', 'Create, open, close, and error states are written back to session records.'],
      ['Cross-platform target', 'The Go backend and static frontend ship together with consistent Linux and Windows deployment paths.'],
    ],
    connectionsTitle: 'Terminal, desktop, transfer, and recording in one workspace',
    connectionsBody:
      'The workspace keeps usability first: terminals and desktops fill the main area while status, clipboard, file transfer, recording state, and disconnect actions stay in the toolbar.',
    openWorkspace: 'Open workspace',
    connectionCards: [
      ['Online SSH terminal', 'A real-time WebSocket to SSH PTY bridge with password, private key, and passphrase authentication plus browser resize sync.'],
      ['RDP remote desktop', 'Windows desktops are rendered through a Guacamole tunnel with keyboard, mouse, clipboard, adaptive resolution, and file transfer.'],
      ['Recording and audit', 'Create, connect, close, and recording download actions are audited, with raw RDP recordings retained locally.'],
    ],
    securityTitle: 'Keep a clear boundary between public pages and real assets',
    securityBody:
      'The homepage is an external entry point; the console is the operations workspace. Sensitive assets, credentials, and session data are never emitted on the public page, and real credentials never reach the browser.',
    securityItems: [
      ['Credentials stay server-side', 'SSH passwords, keys, and RDP accounts are decrypted only on the server. The frontend handles output, pixels, and input events.'],
      ['Local encrypted storage', 'A server-side master key protects secrets while the database stores only ciphertext and required indexes.'],
      ['Resources require sign-in', 'Server lists, credentials, sessions, and audit logs are only available through authenticated workspace APIs.'],
    ],
    workflowTitle: 'From host registration to audit trail with only the necessary steps',
    workflowBody:
      'Phase one does not expand into full monitoring, alerts, or batch jobs. It stabilizes the connection loop first: assets, credentials, sessions, recordings, and audits.',
    workflowSteps: [
      ['01', 'Register server', 'Record Linux / Windows hosts, connection ports, system type, and grouping.'],
      ['02', 'Store credential', 'Create SSH or RDP credentials with sensitive fields encrypted only on the backend.'],
      ['03', 'Start connection', 'Open an SSH terminal or RDP desktop from server details into the fullscreen workspace.'],
      ['04', 'Keep audit trail', 'Session state, close reasons, recording files, and key actions remain traceable.'],
    ],
    deployTitle: 'Deployment shape',
    deployBody: 'Default listener is 23876 and can be overridden by environment variables.',
    footerBody: 'A self-hosted online server connection workspace that keeps SSH, RDP, credentials, recordings, and audit inside one access boundary.',
    footerBuilt: 'Built for browser-based SSH and RDP access.',
    footerProduct: 'Product',
    footerLinks: ['Capabilities', 'Connection workspace', 'Security boundary', 'Deployment shape'],
  },
} as const

const capabilityIcons = [Server, DatabaseZap, RadioTower, CloudCog]
const connectionIcons = [TerminalSquare, MonitorUp, ClipboardCheck]
const securityIcons = [LockKeyhole, KeyRound, ShieldCheck]

export function HomePage() {
  const { auth, locale, publicConfig, setupRequired, t } = useApp()
  const copy = homeCopy[locale]
  const authenticated = Boolean(auth)
  const entryTo = authenticated ? '/app' : '/login'
  const entryText = authenticated ? t('enterConsole') : setupRequired ? t('initializeAdmin') : t('signInConsole')
  const siteName = publicConfig.site_name || 'ServerManager'

  return (
    <div className='min-h-svh overflow-x-clip bg-background text-foreground'>
      <PublicHeader authenticated={authenticated} />
      <main>
        <section className='relative isolate overflow-hidden border-b border-border bg-background pt-24 pb-10 md:pt-28 lg:min-h-[min(760px,82svh)]'>
          <div aria-hidden='true' className='absolute inset-0 bg-[linear-gradient(180deg,color-mix(in_oklch,var(--muted)_42%,transparent)_0%,transparent_42%)]' />
          <div className='absolute inset-x-0 bottom-0 h-32 bg-gradient-to-t from-background to-transparent' aria-hidden='true' />
          <div className='relative z-10 mx-auto grid w-[min(72rem,calc(100%-2rem))] items-center gap-8 lg:grid-cols-[minmax(0,0.82fr)_minmax(390px,0.9fr)] lg:gap-10'>
            <div className='max-w-2xl lg:max-w-[35rem]'>
              <div className='landing-animate inline-flex max-w-full items-center gap-2 rounded-full border border-border bg-background/75 px-3 py-1.5 text-[11px] font-medium text-muted-foreground shadow-sm backdrop-blur-xl'>
                <span className='pulse-dot relative size-1.5 shrink-0 rounded-full bg-success before:absolute before:inset-0 before:rounded-full before:bg-success' />
                <span className='truncate'>{copy.badge}</span>
              </div>
              <h1 className='landing-animate mt-5 text-[clamp(2.7rem,5.6vw,4.65rem)] leading-[0.96] font-semibold tracking-tight' style={{ animationDelay: '60ms' }}>
                {siteName}
              </h1>
              <p className='landing-animate mt-6 max-w-xl text-base leading-8 text-foreground/70 md:text-lg' style={{ animationDelay: '120ms' }}>
                {copy.heroBody}
              </p>
              <div className='landing-animate mt-8 flex flex-wrap items-center gap-3' style={{ animationDelay: '180ms' }}>
                <Link to={entryTo} className={cn(buttonVariants({ variant: 'primary', size: 'lg' }), 'h-10 px-4')}>
                  {entryText}
                  <ArrowRight className='size-4' />
                </Link>
                <Button variant='outline' size='lg' className='h-10 px-4' onClick={() => document.querySelector('#product')?.scrollIntoView({ behavior: 'smooth' })}>
                  {copy.viewProduct}
                </Button>
              </div>
              <div className='landing-animate mt-8 grid max-w-xl grid-cols-2 gap-2 sm:grid-cols-4' style={{ animationDelay: '240ms' }}>
                {copy.highlights.map((item) => (
                  <span key={item} className='rounded-lg border border-border bg-background/70 px-3 py-2 text-xs font-medium text-muted-foreground shadow-sm backdrop-blur-xl'>
                    {item}
                  </span>
                ))}
              </div>
            </div>
            <HeroOperationsPreview />
          </div>
        </section>

        <section id='product' className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 py-16 lg:grid-cols-[0.9fr_1.1fr]'>
          <SectionIntro eyebrow='Product' title={copy.productTitle} body={copy.productBody} />
          <div className='grid gap-3 sm:grid-cols-2'>
            {copy.capabilities.map(([title, body], index) => (
              <CapabilityTile key={title} icon={capabilityIcons[index]} title={title} body={body} />
            ))}
          </div>
        </section>

        <section id='connections' className='border-y border-border bg-muted/30 py-16'>
          <div className='mx-auto w-[min(72rem,calc(100%-2rem))]'>
            <div className='mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-end'>
              <SectionIntro eyebrow='Connections' title={copy.connectionsTitle} body={copy.connectionsBody} />
              <Link to={entryTo} className={cn(buttonVariants({ variant: 'outline', size: 'lg' }), 'h-10 px-4')}>
                {copy.openWorkspace}
                <ChevronRight className='size-4' />
              </Link>
            </div>
            <div className='grid grid-cols-1 gap-3 md:grid-cols-3'>
              {copy.connectionCards.map(([title, body], index) => (
                <FeatureCard key={title} icon={connectionIcons[index]} title={title} body={body} />
              ))}
            </div>
          </div>
        </section>

        <section id='security' className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 py-16 lg:grid-cols-[0.82fr_1.18fr]'>
          <SectionIntro eyebrow='Security' title={copy.securityTitle} body={copy.securityBody} />
          <div className='grid gap-3'>
            {copy.securityItems.map(([title, body], index) => (
              <SecurityRow key={title} icon={securityIcons[index]} title={title} body={body} />
            ))}
          </div>
        </section>

        <section id='deploy' className='border-y border-border bg-card/45 py-16'>
          <div className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 lg:grid-cols-[1fr_0.9fr]'>
            <div>
              <SectionIntro eyebrow='Workflow' title={copy.workflowTitle} body={copy.workflowBody} />
              <div className='mt-8 grid gap-3 sm:grid-cols-2'>
                {copy.workflowSteps.map(([index, title, body]) => (
                  <WorkflowStep key={index} index={index} title={title} body={body} />
                ))}
              </div>
            </div>
            <DeploymentPanel title={copy.deployTitle} body={copy.deployBody} />
          </div>
        </section>
      </main>
      <PublicFooter entryTo={entryTo} entryText={entryText} copy={copy} />
    </div>
  )
}

function HeroOperationsPreview() {
  return (
    <div className='landing-animate w-full max-w-[34rem] justify-self-center lg:justify-self-end' style={{ animationDelay: '140ms' }}>
      <div className='overflow-hidden rounded-2xl border border-border/80 bg-card/85 shadow-2xl backdrop-blur-xl'>
        <div className='flex h-11 min-w-0 items-center gap-2 border-b border-border px-4'>
          <span className='size-2.5 shrink-0 rounded-full bg-destructive' />
          <span className='size-2.5 shrink-0 rounded-full bg-warning' />
          <span className='size-2.5 shrink-0 rounded-full bg-success' />
          <span className='ml-2 min-w-0 truncate rounded-md bg-muted px-2 py-1 font-mono text-[11px] text-muted-foreground sm:ml-4'>workspace / production-west</span>
        </div>
        <div className='grid min-h-[340px] grid-cols-[8rem_minmax(0,1fr)] sm:min-h-[410px] sm:grid-cols-[11rem_minmax(0,1fr)]'>
          <div className='min-w-0 border-r border-border bg-muted/35 p-3 sm:p-4'>
            <div className='mb-4 h-7 rounded-lg bg-background/80' />
            {['Ubuntu gateway', 'Windows admin', 'Database node', 'Build runner'].map((item, index) => (
              <div key={item} className={cn('mb-2 rounded-lg border p-2 text-[11px] sm:p-3 sm:text-xs', index === 1 ? 'border-info/40 bg-info/10 text-foreground' : 'border-border bg-card/75 text-muted-foreground')}>
                <div className='mb-2 flex min-w-0 items-center gap-2'>
                  <span className={cn('size-2 shrink-0 rounded-full', index === 2 ? 'bg-warning' : 'bg-success')} />
                  <span className='truncate font-medium'>{item}</span>
                </div>
                <div className='truncate font-mono text-[10px] opacity-75'>10.18.{index + 12}.24</div>
              </div>
            ))}
          </div>
          <div className='grid min-w-0 content-start gap-3 p-3 sm:p-4'>
            <div className='grid gap-3 xl:grid-cols-[1fr_0.72fr]'>
              <div className='rounded-xl bg-[#050507] p-3 font-mono text-[11px] leading-6 text-zinc-300 shadow-[inset_0_0_0_1px_rgb(255_255_255_/_0.08)] sm:p-4'>
                <div>$ ssh ubuntu@10.18.12.24</div>
                <div>Welcome to Ubuntu 24.04 LTS</div>
                <div>$ systemctl status app</div>
                <div className='text-emerald-300'>active (running)</div>
              </div>
              <div className='rounded-xl border border-border bg-[linear-gradient(180deg,color-mix(in_oklch,var(--info)_18%,var(--card)),var(--card))] p-3'>
                <div className='mb-3 flex items-center justify-between gap-2 text-[11px] text-muted-foreground'>
                  <span>RDP Desktop</span>
                  <span>1920 x 1080</span>
                </div>
                <div className='h-20 rounded-lg bg-background/70 sm:h-24' />
                <div className='mt-3 grid grid-cols-3 gap-2'>
                  <span className='h-7 rounded-md bg-background/60 sm:h-8' />
                  <span className='h-7 rounded-md bg-background/60 sm:h-8' />
                  <span className='h-7 rounded-md bg-background/60 sm:h-8' />
                </div>
              </div>
            </div>
            <div className='grid grid-cols-1 gap-2 sm:grid-cols-3 sm:gap-3'>
              <SceneMetric icon={FileUp} label='Upload' value='24 MB' />
              <SceneMetric icon={Download} label='Recording' value='00:18:42' />
              <SceneMetric icon={Network} label='Latency' value='28 ms' />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function SceneMetric({ icon: Icon, label, value }: { icon: LucideIcon; label: string; value: string }) {
  return (
    <div className='rounded-xl border border-border bg-card/75 p-3'>
      <Icon className='mb-2 size-4 text-muted-foreground sm:mb-3' />
      <div className='text-xs text-muted-foreground'>{label}</div>
      <div className='mt-1 font-mono text-sm font-semibold'>{value}</div>
    </div>
  )
}

function SectionIntro({ eyebrow, title, body }: { eyebrow: string; title: string; body: string }) {
  return (
    <div className='max-w-2xl'>
      <div className='text-xs font-semibold tracking-[0.14em] text-muted-foreground uppercase'>{eyebrow}</div>
      <h2 className='mt-3 text-2xl leading-tight font-semibold tracking-tight md:text-3xl'>{title}</h2>
      <p className='mt-4 text-sm leading-7 text-muted-foreground'>{body}</p>
    </div>
  )
}

function CapabilityTile({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <article className='rounded-xl border border-border bg-card p-5 shadow-sm'>
      <Icon className='mb-5 size-5 text-muted-foreground' />
      <h3 className='text-sm font-semibold'>{title}</h3>
      <p className='mt-2 text-sm leading-6 text-muted-foreground'>{body}</p>
    </article>
  )
}

function FeatureCard({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <Card className='p-5 shadow-sm' data-card-hover='false'>
      <Icon className='mb-5 size-5 text-muted-foreground' />
      <h3 className='text-sm font-semibold'>{title}</h3>
      <p className='text-sm leading-6 text-muted-foreground'>{body}</p>
    </Card>
  )
}

function SecurityRow({ icon: Icon, title, body }: { icon: LucideIcon; title: string; body: string }) {
  return (
    <article className='grid grid-cols-[2.25rem_1fr] gap-4 rounded-xl border border-border bg-card p-5 shadow-sm'>
      <span className='grid size-9 place-items-center rounded-lg bg-muted text-muted-foreground'>
        <Icon className='size-4' />
      </span>
      <div>
        <h3 className='text-sm font-semibold'>{title}</h3>
        <p className='mt-1 text-sm leading-6 text-muted-foreground'>{body}</p>
      </div>
    </article>
  )
}

function WorkflowStep({ index, title, body }: { index: string; title: string; body: string }) {
  return (
    <article className='rounded-xl border border-border bg-background p-5 shadow-sm'>
      <span className='font-mono text-xs font-semibold text-muted-foreground'>{index}</span>
      <h3 className='mt-3 text-sm font-semibold'>{title}</h3>
      <p className='mt-2 text-sm leading-6 text-muted-foreground'>{body}</p>
    </article>
  )
}

function DeploymentPanel({ title, body }: { title: string; body: string }) {
  return (
    <aside className='self-start rounded-xl border border-border bg-background p-5 shadow-sm lg:sticky lg:top-24'>
      <div className='mb-5 flex items-center justify-between gap-3'>
        <div>
          <h3 className='text-sm font-semibold'>{title}</h3>
          <p className='mt-1 text-xs text-muted-foreground'>{body}</p>
        </div>
        <CheckCircle2 className='size-5 text-success' />
      </div>
      <div className='grid gap-2 font-mono text-xs'>
        <div className='rounded-lg bg-muted p-3'>SERVERMANAGER_ADDR=0.0.0.0:23876</div>
        <div className='rounded-lg bg-muted p-3'>SERVERMANAGER_DATA_DIR=/opt/servermanager/data</div>
        <div className='rounded-lg bg-muted p-3'>SERVERMANAGER_GUACD_HOST=127.0.0.1</div>
      </div>
      <div className='mt-5 grid grid-cols-2 gap-2 text-xs text-muted-foreground'>
        <span className='rounded-lg border border-border px-3 py-2'>Linux</span>
        <span className='rounded-lg border border-border px-3 py-2'>Windows</span>
        <span className='rounded-lg border border-border px-3 py-2'>SQLite</span>
        <span className='rounded-lg border border-border px-3 py-2'>guacd</span>
      </div>
    </aside>
  )
}

function PublicFooter({ entryTo, entryText, copy }: { entryTo: string; entryText: string; copy: (typeof homeCopy)['zh-CN'] | (typeof homeCopy)['en-US'] }) {
  return (
    <footer className='border-t border-border bg-background'>
      <div className='mx-auto grid w-[min(72rem,calc(100%-2rem))] gap-8 py-10 md:grid-cols-[1.2fr_0.8fr_0.8fr]'>
        <div>
          <div className='inline-flex items-center gap-2 text-sm font-semibold'>
            <span className='grid size-6 place-items-center rounded-md bg-primary text-primary-foreground'>
              <span className='size-3 rounded-sm bg-primary-foreground/90' />
            </span>
            ServerManager
          </div>
          <p className='mt-3 max-w-sm text-sm leading-6 text-muted-foreground'>{copy.footerBody}</p>
        </div>
        <FooterColumn
          title={copy.footerProduct}
          links={[
            [copy.footerLinks[0], '#product'],
            [copy.footerLinks[1], '#connections'],
            [copy.footerLinks[2], '#security'],
            [copy.footerLinks[3], '#deploy'],
          ]}
        />
        <div>
          <h3 className='text-xs font-semibold tracking-[0.12em] text-muted-foreground uppercase'>Console</h3>
          <Link to={entryTo} className={cn(buttonVariants({ variant: 'outline', size: 'lg' }), 'mt-4 h-10 w-full px-4 md:w-auto')}>
            {entryText}
            <ArrowRight className='size-4' />
          </Link>
        </div>
      </div>
      <div className='mx-auto flex w-[min(72rem,calc(100%-2rem))] flex-col gap-2 border-t border-border py-5 text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between'>
        <span>© 2026 ServerManager. Self-hosted server operations console.</span>
        <span>{copy.footerBuilt}</span>
      </div>
    </footer>
  )
}

function FooterColumn({ title, links }: { title: string; links: Array<[string, string]> }) {
  return (
    <nav>
      <h3 className='text-xs font-semibold tracking-[0.12em] text-muted-foreground uppercase'>{title}</h3>
      <div className='mt-4 grid gap-2'>
        {links.map(([label, href]) => (
          <a key={href} href={href} className='text-sm text-muted-foreground transition-colors hover:text-foreground'>
            {label}
          </a>
        ))}
      </div>
    </nav>
  )
}
