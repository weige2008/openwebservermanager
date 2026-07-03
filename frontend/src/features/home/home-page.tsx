import { Link } from '@tanstack/react-router'
import { ArrowRight, CircleDot, KeyRound, MonitorUp, Server, ShieldCheck, TerminalSquare } from 'lucide-react'

import { useApp } from '@/app/app-provider'
import { PublicHeader } from '@/components/layout/public-header'
import { Button } from '@/components/ui/button'
import { buttonVariants } from '@/components/ui/button'
import { Card } from '@/components/ui/card'

export function HomePage() {
  const { auth, setupRequired } = useApp()
  const authenticated = Boolean(auth)
  const entryTo = authenticated ? '/app' : '/login'
  const entryText = authenticated ? '进入控制台' : setupRequired ? '初始化管理员' : '登录控制台'

  return (
    <div className='min-h-svh overflow-x-clip bg-background text-foreground'>
      <PublicHeader authenticated={authenticated} />
      <main>
        <section className='mx-auto grid min-h-[720px] w-[min(72rem,calc(100%-2rem))] grid-cols-1 items-center gap-12 pt-32 pb-14 lg:grid-cols-[minmax(0,1fr)_minmax(420px,0.92fr)]'>
          <div className='flex flex-col items-start'>
            <div className='landing-animate inline-flex items-center gap-2 rounded-full border border-info/20 bg-info/7 px-3 py-1.5 text-[11px] font-medium text-info'>
              <span className='pulse-dot relative size-1.5 rounded-full bg-info before:absolute before:inset-0 before:rounded-full before:bg-info' />
              在线服务器管理第一阶段
            </div>
            <h1 className='landing-animate mt-5 max-w-3xl text-[clamp(2.3rem,5vw,4.6rem)] leading-[1.05] font-bold tracking-tight' style={{ animationDelay: '60ms' }}>
              浏览器里的 SSH 终端与 RDP 桌面
            </h1>
            <p className='landing-animate mt-5 max-w-xl text-base leading-relaxed text-muted-foreground' style={{ animationDelay: '120ms' }}>
              面向 Linux 和 Windows 服务器的统一连接工作台。凭据只在服务端加密保存，浏览器只负责终端、桌面渲染和输入事件。
            </p>
            <div className='landing-animate mt-8 flex flex-wrap items-center gap-3' style={{ animationDelay: '180ms' }}>
              <Link to={entryTo} className={buttonVariants({ variant: 'primary', size: 'lg' })}>
                {entryText}
                <ArrowRight className='size-4' />
              </Link>
              <Button variant='outline' size='lg' onClick={() => document.querySelector('#features')?.scrollIntoView({ behavior: 'smooth' })}>
                查看能力
              </Button>
            </div>
            <div className='landing-animate mt-9 flex flex-wrap gap-2' style={{ animationDelay: '240ms' }}>
              {['SSH PTY', 'Guacamole RDP', '录屏审计', '文件传输'].map((item) => (
                <span key={item} className='rounded-full border border-border bg-muted/55 px-3 py-1.5 text-xs font-semibold'>
                  {item}
                </span>
              ))}
            </div>
          </div>
          <HeroWorkspacePreview />
        </section>

        <section id='features' className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-3 md:grid-cols-3'>
          <FeatureCard icon={TerminalSquare} title='SSH' body='浏览器 WebSocket 到服务端 SSH PTY，支持密码、私钥与 passphrase。' />
          <FeatureCard icon={MonitorUp} title='RDP' body='Go tunnel 接入 guacd，前端只渲染桌面与键鼠输入。' />
          <FeatureCard icon={ShieldCheck} title='审计' body='会话、断开、录屏下载与关键操作写入审计日志。' />
        </section>

        <section id='security' className='mx-auto mt-6 grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 items-center gap-8 rounded-xl border border-border bg-card p-7 shadow-sm lg:grid-cols-[minmax(0,0.95fr)_minmax(280px,1fr)]'>
          <div>
            <div className='text-xs font-medium tracking-[0.12em] text-muted-foreground uppercase'>Security Boundary</div>
            <h2 className='mt-2 text-3xl font-semibold tracking-tight'>登录后才进入服务器资产区</h2>
            <p className='mt-2 text-sm leading-relaxed text-muted-foreground'>
              公开首页不展示服务器列表、凭据、会话或审计日志。所有连接 API、WebSocket 与录屏下载都需要有效管理员会话。
            </p>
          </div>
          <div className='flex flex-wrap gap-2 lg:justify-end'>
            {['HttpOnly Cookie 会话', '凭据不下发浏览器', 'AES-GCM 本地加密存储', '连接操作审计'].map((item) => (
              <span key={item} className='rounded-full border border-border bg-muted/55 px-3 py-1.5 text-xs font-semibold'>
                {item}
              </span>
            ))}
          </div>
        </section>

        <section id='workflow' className='mx-auto grid w-[min(72rem,calc(100%-2rem))] grid-cols-1 gap-3 py-6 pb-12 md:grid-cols-3'>
          <WorkflowStep index='1' title='登记服务器' body='记录主机、系统、SSH/RDP 端口与分组。' />
          <WorkflowStep index='2' title='保存凭据' body='密码、私钥、域账号只在后端加密保存。' />
          <WorkflowStep index='3' title='打开工作区' body='SSH 与 RDP 全屏连接，顶部保留状态与断开操作。' />
        </section>
      </main>
    </div>
  )
}

function HeroWorkspacePreview() {
  return (
    <Card className='landing-animate overflow-hidden rounded-[1.35rem] shadow-2xl' style={{ animationDelay: '300ms' }}>
      <div className='flex h-11 items-center gap-2 border-b border-border px-3'>
        <span className='size-2.5 rounded-full bg-destructive' />
        <span className='size-2.5 rounded-full bg-warning' />
        <span className='size-2.5 rounded-full bg-success' />
        <span className='ml-auto font-mono text-xs text-muted-foreground'>session://rdp/sess_live</span>
      </div>
      <div className='grid min-h-[430px] grid-cols-[76px_1fr] bg-[radial-gradient(circle_at_70%_12%,color-mix(in_oklch,var(--info)_18%,transparent),transparent_32%),var(--background)] max-sm:grid-cols-1'>
        <div className='grid content-start gap-3 border-r border-border p-4 max-sm:hidden'>
          {[0, 1, 2, 3].map((item) => (
            <span key={item} className='h-9 rounded-xl bg-muted' />
          ))}
        </div>
        <div className='grid gap-4 p-5'>
          <div className='grid min-h-44 content-start gap-2 rounded-2xl bg-[#030305] p-5 font-mono text-xs text-zinc-300 shadow-[inset_0_0_0_1px_rgb(255_255_255_/_0.08)]'>
            <code>$ ssh ubuntu@server</code>
            <code>Welcome to Ubuntu 24.04 LTS</code>
            <code>$ systemctl status nginx</code>
            <code className='text-emerald-300'>active (running)</code>
          </div>
          <div className='grid min-h-48 grid-cols-[1fr_0.62fr] gap-4'>
            <div className='rounded-2xl border border-border bg-[linear-gradient(180deg,color-mix(in_oklch,var(--info)_18%,var(--card)),var(--card))]' />
            <div className='rounded-2xl border border-border bg-[linear-gradient(180deg,color-mix(in_oklch,var(--success)_12%,var(--card)),var(--card))]' />
          </div>
        </div>
      </div>
    </Card>
  )
}

function FeatureCard({ icon: Icon, title, body }: { icon: typeof Server; title: string; body: string }) {
  return (
    <article className='rounded-xl border border-border bg-card p-5 shadow-sm'>
      <Icon className='mb-4 size-5 text-muted-foreground' />
      <span className='text-sm font-semibold'>{title}</span>
      <p className='mt-2 text-sm text-muted-foreground'>{body}</p>
    </article>
  )
}

function WorkflowStep({ index, title, body }: { index: string; title: string; body: string }) {
  return (
    <article className='rounded-xl border border-border bg-card p-5 shadow-sm'>
      <span className='mb-3 inline-flex size-8 items-center justify-center rounded-lg border border-border bg-muted font-semibold'>{index}</span>
      <strong className='block'>{title}</strong>
      <p className='mt-2 text-sm text-muted-foreground'>{body}</p>
      <CircleDot className='mt-5 size-4 text-muted-foreground' />
    </article>
  )
}
