import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import { Clipboard, Power, Upload } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'

import { useApp } from '@/app/app-provider'
import { apiRequest } from '@/lib/api'
import { base64ToText, textToBase64 } from '@/lib/codec'
import type { ConnectionSession } from '@/types'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

export function WorkspaceView() {
  const app = useApp()
  const workspace = app.workspace
  const [status, setStatus] = useState(workspace?.status || 'connecting')

  if (!workspace) return null

  const server = app.data.servers.find((item) => item.id === workspace.session.server_id)

  const leave = async () => {
    app.setWorkspace(null)
    await app.refresh(true)
  }

  const close = async () => {
    await apiRequest(`/api/connections/${workspace.session.id}/close`, { method: 'POST', body: '{}' })
    app.setWorkspace(null)
    await app.refresh(true)
  }

  return (
    <div className='grid min-h-svh grid-rows-[52px_minmax(0,1fr)] bg-[#050506] text-zinc-100'>
      <div className='flex min-w-0 items-center justify-between gap-3 border-b border-white/10 bg-[#0d0d10] px-3 max-md:h-auto max-md:flex-col max-md:items-start max-md:py-3'>
        <div className='flex min-w-0 items-center gap-2'>
          <strong>{workspace.session.protocol.toUpperCase()}</strong>
          <span className='truncate text-zinc-400'>{server?.name || workspace.session.server_id}</span>
          <Badge tone={status === 'connected' ? 'success' : 'neutral'}>{status}</Badge>
          {workspace.session.protocol === 'rdp' ? <Badge tone='danger'>录屏中</Badge> : null}
        </div>
        <div className='flex flex-wrap gap-2'>
          {workspace.type === 'rdp' ? (
            <>
              <Button variant='outline' onClick={() => window.dispatchEvent(new Event('servermanager:rdp-clipboard'))}><Clipboard className='size-4' />剪贴板</Button>
              <Button variant='outline' onClick={() => window.dispatchEvent(new Event('servermanager:rdp-upload'))}><Upload className='size-4' />上传文件</Button>
            </>
          ) : null}
          <Button variant='outline' onClick={() => void leave()}>返回控制台</Button>
          <Button variant='destructive' onClick={() => void close()}><Power className='size-4' />断开</Button>
        </div>
      </div>
      {workspace.type === 'ssh' ? (
        <SSHWorkspace session={workspace.session} setStatus={setStatus} />
      ) : (
        <RDPWorkspace session={workspace.session} setStatus={setStatus} showToast={app.showToast} />
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

  return <div ref={containerRef} className='h-[calc(100vh-52px)] bg-[#030305] p-3 max-md:h-[calc(100vh-120px)]' />
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

  return <div ref={containerRef} className='h-[calc(100vh-52px)] overflow-hidden bg-[#020204] max-md:h-[calc(100vh-120px)]' />
}
