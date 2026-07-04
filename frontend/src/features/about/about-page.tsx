import { Link } from '@tanstack/react-router'
import { Github, LockKeyhole, MonitorUp, PackageCheck, Server, ShieldCheck } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { PublicHeader } from '@/components/layout/public-header'
import { SystemBrand } from '@/components/layout/system-brand'
import { buttonVariants } from '@/components/ui/button'
import { cn } from '@/lib/utils'

export function PublicAboutPage() {
  const app = useApp()
  const entryTo = app.auth ? '/app' : '/login'
  const entryText = app.auth ? app.t('enterConsole') : app.setupRequired ? app.t('initializeAdmin') : app.t('signInConsole')

  return (
    <div className='min-h-svh bg-background text-foreground'>
      <PublicHeader authenticated={Boolean(app.auth)} />
      <main className='px-6 pt-28 pb-16 md:pt-36'>
        <div className='mx-auto max-w-5xl'>
          <AboutContent />
          <div className='mt-8 flex flex-wrap gap-3'>
            <Link to={entryTo} className={cn(buttonVariants({ variant: 'primary' }), 'rounded-lg')}>
              {entryText}
            </Link>
            <GitHubButton />
          </div>
        </div>
      </main>
      <AboutFooter />
    </div>
  )
}

export function ConsoleAboutPage() {
  return (
    <div className='grid gap-4'>
      <AboutContent />
    </div>
  )
}

function AboutContent() {
  const app = useApp()
  const { t } = useTranslation()
  const version = app.publicConfig.version || 'dev'
  const productName = t('productName')

  return (
    <section className='grid gap-4'>
      <div className='rounded-xl border border-border bg-card p-5 shadow-sm'>
        <div className='flex flex-wrap items-start justify-between gap-4'>
          <div>
            <p className='text-xs font-medium tracking-[0.14em] text-muted-foreground uppercase'>{t('about')}</p>
            <h1 className='mt-2 text-2xl font-semibold tracking-tight md:text-3xl'>{t('aboutPage.title', { productName })}</h1>
            <p className='mt-3 max-w-3xl text-sm leading-6 text-muted-foreground'>{t('aboutPage.description', { productName })}</p>
          </div>
          <div className='rounded-lg border border-border bg-muted/30 px-3 py-2 font-mono text-xs'>
            {t('version')} {version}
          </div>
        </div>
      </div>

      <div className='grid gap-4 md:grid-cols-2 xl:grid-cols-4'>
        <AboutCard icon={Server} title={t('aboutPage.assetsTitle')} body={t('aboutPage.assetsBody')} />
        <AboutCard icon={MonitorUp} title={t('aboutPage.workspaceTitle')} body={t('aboutPage.workspaceBody')} />
        <AboutCard icon={LockKeyhole} title={t('aboutPage.securityTitle')} body={t('aboutPage.securityBody')} />
        <AboutCard icon={PackageCheck} title={t('aboutPage.releaseTitle')} body={t('aboutPage.releaseBody')} />
      </div>

      <div className='grid gap-4 rounded-xl border border-border bg-card p-5 shadow-sm lg:grid-cols-[1fr_0.9fr]'>
        <div>
          <h2 className='text-base font-semibold'>{t('aboutPage.boundaryTitle')}</h2>
          <p className='mt-2 text-sm leading-6 text-muted-foreground'>{t('aboutPage.boundaryBody')}</p>
        </div>
        <div className='grid gap-2 rounded-lg border border-border bg-muted/25 p-3 text-sm'>
          <InfoRow label={t('github')} value={app.publicConfig.github_url || 'https://github.com/weige2008/openwebservermanager'} />
          <InfoRow label={t('version')} value={version} />
          <InfoRow label={t('copyright')} value={app.publicConfig.copyright || 'Copyright (c) 2026 weige2008. All rights reserved.'} />
        </div>
      </div>
    </section>
  )
}

function AboutCard({ icon: Icon, title, body }: { icon: typeof ShieldCheck; title: string; body: string }) {
  return (
    <article className='rounded-xl border border-border bg-card p-5 shadow-sm'>
      <span className='grid size-10 place-items-center rounded-lg bg-gradient-to-br from-blue-500/15 via-violet-500/10 to-amber-500/15 text-blue-500 ring-1 ring-border'>
        <Icon className='size-5' />
      </span>
      <h2 className='mt-4 text-sm font-semibold'>{title}</h2>
      <p className='mt-2 text-sm leading-6 text-muted-foreground'>{body}</p>
    </article>
  )
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className='flex min-w-0 items-center justify-between gap-3'>
      <span className='shrink-0 text-muted-foreground'>{label}</span>
      <span className='truncate text-right font-mono text-xs'>{value}</span>
    </div>
  )
}

function GitHubButton() {
  const app = useApp()
  const { t } = useTranslation()
  const href = app.publicConfig.github_url || 'https://github.com/weige2008/openwebservermanager'

  return (
    <a href={href} target='_blank' rel='noreferrer' className={cn(buttonVariants({ variant: 'outline' }), 'rounded-lg')}>
      <Github className='size-4' />
      {t('github')}
    </a>
  )
}

function AboutFooter() {
  const app = useApp()
  return (
    <footer className='border-t border-border bg-background'>
      <div className='mx-auto flex w-[min(72rem,calc(100%-2rem))] flex-col gap-3 py-6 text-xs text-muted-foreground sm:flex-row sm:items-center sm:justify-between'>
        <SystemBrand clickable />
        <span>{app.publicConfig.copyright || 'Copyright (c) 2026 weige2008. All rights reserved.'}</span>
      </div>
    </footer>
  )
}
