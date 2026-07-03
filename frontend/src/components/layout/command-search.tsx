import { useNavigate } from '@tanstack/react-router'
import { Activity, FileClock, KeyRound, MonitorUp, Plus, SearchIcon, Server } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'

import { useApp } from '@/app/app-provider'
import { DialogShell } from '@/components/ui/dialog'
import { Input } from '@/components/ui/field'
import { cn } from '@/lib/utils'

import { Button } from '../ui/button'

type CommandItem = {
  id: string
  label: string
  description: string
  icon: typeof SearchIcon
  run: () => void | Promise<void>
}

export function CommandSearch() {
  const app = useApp()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setOpen(true)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  const close = () => {
    setOpen(false)
    setQuery('')
  }

  const commands = useMemo<CommandItem[]>(
    () => [
      { id: 'overview', label: '总览', description: '查看连接工作区概览', icon: Activity, run: () => navigate({ to: '/app' }) },
      { id: 'servers', label: '服务器', description: '查看服务器资产列表', icon: Server, run: () => navigate({ to: '/app/servers' }) },
      { id: 'credentials', label: '凭据', description: '管理 SSH / RDP 凭据', icon: KeyRound, run: () => navigate({ to: '/app/credentials' }) },
      { id: 'sessions', label: '连接会话', description: '查看 SSH / RDP 会话', icon: MonitorUp, run: () => navigate({ to: '/app/sessions' }) },
      { id: 'audit', label: '审计日志', description: '查看登录、连接和录屏访问记录', icon: FileClock, run: () => navigate({ to: '/app/audit' }) },
      { id: 'new-server', label: '新增服务器', description: '登记 Linux 或 Windows 服务器', icon: Plus, run: () => app.setModal({ type: 'server' }) },
      { id: 'new-credential', label: '新增凭据', description: '保存 SSH 密码、私钥或 RDP 账号', icon: Plus, run: () => app.setModal({ type: 'credential' }) },
      ...app.data.servers.map((server) => ({
        id: `server:${server.id}`,
        label: server.name,
        description: `${server.host} · ${server.os}`,
        icon: Server,
        run: () => app.setModal({ type: 'connect', protocol: server.os === 'windows' ? 'rdp' : 'ssh', serverId: server.id }),
      })),
    ],
    [app, navigate]
  )

  const normalizedQuery = query.trim().toLowerCase()
  const visibleCommands = normalizedQuery
    ? commands.filter((item) => `${item.label} ${item.description}`.toLowerCase().includes(normalizedQuery))
    : commands.slice(0, 10)

  const runCommand = async (item: CommandItem) => {
    await item.run()
    close()
  }

  return (
    <>
      <Button
        variant='outline'
        className='group inline-flex h-8 min-w-0 flex-1 justify-start rounded-md bg-muted/25 text-sm font-normal text-muted-foreground shadow-none sm:w-44 sm:flex-none lg:w-60 xl:w-72'
        onClick={() => setOpen(true)}
        aria-label='搜索'
      >
        <SearchIcon className='size-4' />
        <span className='truncate'>搜索服务器、凭据、会话</span>
        <kbd className='ms-auto hidden h-5 items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium group-hover:bg-accent lg:flex'>
          Ctrl K
        </kbd>
      </Button>
      <DialogShell compact open={open} onOpenChange={setOpen} title='搜索' description='快速跳转、创建资源或打开服务器连接。'>
        <div className='grid gap-3'>
          <Input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder='输入服务器、页面或操作名称' />
          <div className='grid max-h-[50vh] gap-1 overflow-auto'>
            {visibleCommands.map((item) => {
              const Icon = item.icon
              return (
                <button
                  key={item.id}
                  className={cn(
                    'flex min-w-0 items-center gap-3 rounded-lg px-2 py-2 text-left text-sm outline-none transition-colors hover:bg-muted focus-visible:bg-muted'
                  )}
                  onClick={() => void runCommand(item)}
                >
                  <span className='grid size-8 shrink-0 place-items-center rounded-md bg-muted text-foreground'>
                    <Icon className='size-4' />
                  </span>
                  <span className='min-w-0'>
                    <span className='block truncate font-medium'>{item.label}</span>
                    <span className='block truncate text-xs text-muted-foreground'>{item.description}</span>
                  </span>
                </button>
              )
            })}
            {!visibleCommands.length ? (
              <div className='rounded-lg border border-dashed border-border p-6 text-center text-sm text-muted-foreground'>没有匹配结果</div>
            ) : null}
          </div>
        </div>
      </DialogShell>
    </>
  )
}
