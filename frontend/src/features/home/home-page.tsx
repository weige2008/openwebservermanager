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
import { Button } from '@/components/ui/button'
import { buttonVariants } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { cn } from '@/lib/utils'

const productHighlights = ['自托管部署', '浏览器直连', '凭据加密', '会话审计']

const connectionCards = [
  {
    icon: TerminalSquare,
    title: 'SSH 在线终端',
    body: '基于 WebSocket 与 SSH PTY 的实时终端，支持密码、私钥和 passphrase，窗口尺寸随浏览器同步。',
  },
  {
    icon: MonitorUp,
    title: 'RDP 远程桌面',
    body: '通过 Guacamole tunnel 接入 Windows 桌面，支持键鼠输入、剪贴板、分辨率自适应与文件传输。',
  },
  {
    icon: ClipboardCheck,
    title: '录屏与审计',
    body: '会话创建、连接、断开、录屏下载等关键动作进入审计链路，RDP 原始录屏本地留存。',
  },
]

const securityItems = [
  {
    icon: LockKeyhole,
    title: '凭据不进入浏览器',
    body: 'SSH 密码、私钥和 RDP 账号仅在服务端解密使用，前端只处理终端输出、桌面画面和输入事件。',
  },
  {
    icon: KeyRound,
    title: '本地加密存储',
    body: '凭据由服务端主密钥保护，数据库只保存密文和必要索引，便于在单机或内网环境落地。',
  },
  {
    icon: ShieldCheck,
    title: '登录后访问资源',
    body: '公开首页不暴露服务器列表、凭据、连接会话或审计日志，所有工作区 API 均需要有效会话。',
  },
]

const workflowSteps = [
  ['01', '登记服务器', '录入 Linux / Windows 主机、连接端口、系统类型和分组信息。'],
  ['02', '保存凭据', '创建 SSH 或 RDP 凭据，敏感字段只在后端加密保存。'],
  ['03', '发起连接', '在服务器详情中打开 SSH 终端或 RDP 桌面，进入全屏工作区。'],
  ['04', '留存审计', '会话状态、断开原因、录屏文件和关键操作可追溯。'],
]

export function HomePage() {
  const { auth, setupRequired, publicConfig } = useApp()
  const authenticated = Boolean(auth)
  const entryTo = authenticated ? '/app' : '/login'
  const entryText = authenticated ? '进入控制台' : setupRequired ? '初始化管理员' : '登录控制台'
  const siteName = publicConfig.site_name || 'ServerManager'

  return (
    <div className='min-h-svh overflow-x-clip bg-background text-foreground'>
      <PublicHeader authenticated={authenticated} />
      <main>
        <section className='relative isolate flex min-h-[78svh] overflow-hidden border-b border-border bg-background pt-24 pb-14 md:pt-28'>
          <HeroOperationsScene />
          <div className='relative z-10 mx-auto flex w-[min(72rem,calc(100%-2rem))] flex-col justify-center'>
            <div className='max-w-3xl'>
              <div className='landing-animate inline-flex items-center gap-2 rounded-full border border-border bg-background/70 px-3 py-1.5 text-[11px] font-medium text-muted-foreground shadow-sm backdrop-blur-xl'>
                <span className='pulse-dot relative size-1.5 rounded-full bg-success before:absolute before:inset-0 before:rounded-full before:bg-success' />
                面向团队的自托管服务器连接工作台
              </div>
              <h1 className='landing-animate mt-5 text-[clamp(3rem,5.8vw,4.8rem)] leading-[0.94] font-semibold tracking-tight' style={{ animationDelay: '60ms' }}>
                {siteName}
              </h1>
              <p className='landing-animate mt-6 max-w-2xl text-base leading-8 text-foreground/70 md:text-lg' style={{ animationDelay: '120ms' }}>
                在浏览器里统一打开 SSH 终端与 RDP 桌面。服务器资产、连接凭据、会话录屏和审计日志集中管理，适合部署在 Linux、Windows
                与内网测试环境中。
              </p>
              <div className='landing-animate mt-8 flex flex-wrap items-center gap-3' style={{ animationDelay: '180ms' }}>
                <Link to={entryTo} className={cn(buttonVariants({ variant: 'primary', size: 'lg' }), 'h-10 px-4')}>
                  {entryText}
                  <ArrowRight className='size-4' />
                </Link>
                <Button variant='outline' size='lg' className='h-10 px-4' onClick={() => document.querySelector('#product')?.scrollIntoView({ behavior: 'smooth' })}>
                  查看产品能力
                </Button>
              </div>
              <div className='landing-animate mt-8 grid max-w-2xl grid-cols-2 gap-2 sm:grid-cols-4' style={{ animationDelay: '240ms' }}>
                {productHighlights.map((item) => (
                  <span key={item} className='rounded-lg border border-border bg-background/65 px-3 py-2 text-xs font-medium text-muted-foreground shadow-sm backdrop-blur-xl'>
                    {item}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section id='product' className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 py-16 lg:grid-cols-[0.9fr_1.1fr]'>
          <SectionIntro
            eyebrow='Product'
            title='把分散的远程连接收进同一个控制台'
            body='ServerManager 的公开页只展示产品信息；登录后才进入服务器列表、凭据管理和连接工作区。首阶段聚焦在线 SSH 与 RDP，让日常登录、排障、文件流转和审计留痕更顺手。'
          />
          <div className='grid gap-3 sm:grid-cols-2'>
            <CapabilityTile icon={Server} title='统一资产入口' body='按系统类型、主机地址和连接端口登记服务器，为 SSH/RDP 会话提供清晰入口。' />
            <CapabilityTile icon={DatabaseZap} title='内置轻量数据层' body='服务器、凭据、会话和审计记录本地保存，默认即可在单机测试环境运行。' />
            <CapabilityTile icon={RadioTower} title='实时连接状态' body='连接创建、打开、断开和错误状态回写会话记录，便于追踪现场。' />
            <CapabilityTile icon={CloudCog} title='跨平台部署目标' body='Go 后端与前端静态资源一体发布，Linux 和 Windows 部署路径保持一致。' />
          </div>
        </section>

        <section id='connections' className='border-y border-border bg-muted/30 py-16'>
          <div className='mx-auto w-[min(72rem,calc(100%-2rem))]'>
            <div className='mb-8 flex flex-col justify-between gap-4 md:flex-row md:items-end'>
              <SectionIntro
                eyebrow='Connections'
                title='终端、桌面、传输与录屏，集中在工作区完成'
                body='连接工作区以可用性优先：主区域留给终端和桌面，顶部保留状态、剪贴板、文件传输、录屏状态和断开操作。'
              />
              <Link to={entryTo} className={cn(buttonVariants({ variant: 'outline', size: 'lg' }), 'h-10 px-4')}>
                打开工作区
                <ChevronRight className='size-4' />
              </Link>
            </div>
            <div className='grid grid-cols-1 gap-3 md:grid-cols-3'>
              {connectionCards.map((card) => (
                <FeatureCard key={card.title} {...card} />
              ))}
            </div>
          </div>
        </section>

        <section id='security' className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 py-16 lg:grid-cols-[0.82fr_1.18fr]'>
          <SectionIntro
            eyebrow='Security'
            title='公开展示和真实资产之间保持明确边界'
            body='首页是对外入口，控制台才是运维工作区。敏感资产、凭据和会话数据不在公开页面输出，连接通道也不会把真实凭据交给浏览器。'
          />
          <div className='grid gap-3'>
            {securityItems.map((item) => (
              <SecurityRow key={item.title} {...item} />
            ))}
          </div>
        </section>

        <section id='deploy' className='border-y border-border bg-card/45 py-16'>
          <div className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-8 lg:grid-cols-[1fr_0.9fr]'>
            <div>
              <SectionIntro
                eyebrow='Workflow'
                title='从登记主机到断开留痕，只保留必要步骤'
                body='第一阶段不扩展完整监控、告警和批量任务，把连接闭环先做稳：资产、凭据、会话、录屏和审计各自清楚。'
              />
              <div className='mt-8 grid gap-3 sm:grid-cols-2'>
                {workflowSteps.map(([index, title, body]) => (
                  <WorkflowStep key={index} index={index} title={title} body={body} />
                ))}
              </div>
            </div>
            <DeploymentPanel />
          </div>
        </section>
      </main>
      <PublicFooter entryTo={entryTo} entryText={entryText} />
    </div>
  )
}

function HeroOperationsScene() {
  return (
    <div aria-hidden='true' className='absolute inset-0 overflow-hidden'>
      <div className='absolute inset-0 bg-[radial-gradient(circle_at_68%_16%,color-mix(in_oklch,var(--info)_20%,transparent),transparent_31%),radial-gradient(circle_at_85%_72%,color-mix(in_oklch,var(--success)_16%,transparent),transparent_30%)]' />
      <div className='absolute inset-x-0 bottom-0 h-1/2 bg-gradient-to-t from-background via-background/65 to-transparent' />
      <div className='absolute top-[18%] right-[max(2rem,calc((100vw-72rem)/2))] hidden w-[min(48rem,42vw)] lg:block'>
        <div className='overflow-hidden rounded-2xl border border-border/80 bg-card/80 shadow-2xl backdrop-blur-xl'>
          <div className='flex h-11 items-center gap-2 border-b border-border px-4'>
            <span className='size-2.5 rounded-full bg-destructive' />
            <span className='size-2.5 rounded-full bg-warning' />
            <span className='size-2.5 rounded-full bg-success' />
            <span className='ml-4 rounded-md bg-muted px-2 py-1 font-mono text-[11px] text-muted-foreground'>workspace / production-west</span>
          </div>
          <div className='grid min-h-[410px] grid-cols-[180px_1fr]'>
            <div className='border-r border-border bg-muted/35 p-4'>
              <div className='mb-4 h-7 rounded-lg bg-background/80' />
              {['Ubuntu gateway', 'Windows admin', 'Database node', 'Build runner'].map((item, index) => (
                <div key={item} className={cn('mb-2 rounded-lg border p-3 text-xs', index === 1 ? 'border-info/40 bg-info/10 text-foreground' : 'border-border bg-card/75 text-muted-foreground')}>
                  <div className='mb-2 flex items-center gap-2'>
                    <span className={cn('size-2 rounded-full', index === 2 ? 'bg-warning' : 'bg-success')} />
                    <span className='font-medium'>{item}</span>
                  </div>
                  <div className='font-mono text-[10px] opacity-75'>10.18.{index + 12}.24</div>
                </div>
              ))}
            </div>
            <div className='grid gap-3 p-4'>
              <div className='grid grid-cols-[1fr_0.72fr] gap-3'>
                <div className='rounded-xl bg-[#050507] p-4 font-mono text-[11px] leading-6 text-zinc-300 shadow-[inset_0_0_0_1px_rgb(255_255_255_/_0.08)]'>
                  <div>$ ssh ubuntu@10.18.12.24</div>
                  <div>Welcome to Ubuntu 24.04 LTS</div>
                  <div>$ systemctl status app</div>
                  <div className='text-emerald-300'>active (running)</div>
                </div>
                <div className='rounded-xl border border-border bg-[linear-gradient(180deg,color-mix(in_oklch,var(--info)_18%,var(--card)),var(--card))] p-3'>
                  <div className='mb-3 flex items-center justify-between text-[11px] text-muted-foreground'>
                    <span>RDP Desktop</span>
                    <span>1920 x 1080</span>
                  </div>
                  <div className='h-24 rounded-lg bg-background/70' />
                  <div className='mt-3 grid grid-cols-3 gap-2'>
                    <span className='h-8 rounded-md bg-background/60' />
                    <span className='h-8 rounded-md bg-background/60' />
                    <span className='h-8 rounded-md bg-background/60' />
                  </div>
                </div>
              </div>
              <div className='grid grid-cols-3 gap-3'>
                <SceneMetric icon={FileUp} label='Upload' value='24 MB' />
                <SceneMetric icon={Download} label='Recording' value='00:18:42' />
                <SceneMetric icon={Network} label='Latency' value='28 ms' />
              </div>
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
      <Icon className='mb-3 size-4 text-muted-foreground' />
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

function DeploymentPanel() {
  return (
    <aside className='self-start rounded-xl border border-border bg-background p-5 shadow-sm lg:sticky lg:top-24'>
      <div className='mb-5 flex items-center justify-between gap-3'>
        <div>
          <h3 className='text-sm font-semibold'>部署形态</h3>
          <p className='mt-1 text-xs text-muted-foreground'>默认监听 23876，可通过环境变量覆盖。</p>
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

function PublicFooter({ entryTo, entryText }: { entryTo: string; entryText: string }) {
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
          <p className='mt-3 max-w-sm text-sm leading-6 text-muted-foreground'>自托管的在线服务器连接工作台，把 SSH、RDP、凭据、录屏和审计放在同一套访问边界内。</p>
        </div>
        <FooterColumn
          title='产品'
          links={[
            ['产品能力', '#product'],
            ['连接工作区', '#connections'],
            ['安全边界', '#security'],
            ['部署形态', '#deploy'],
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
        <span>Built for browser-based SSH and RDP access.</span>
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
