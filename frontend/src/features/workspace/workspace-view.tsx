import { FitAddon } from '@xterm/addon-fit'
import { Terminal } from '@xterm/xterm'
import { Clipboard, Power, Upload } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { apiRequest } from '@/lib/api'
import { base64ToText, textToBase64 } from '@/lib/codec'
import { statusLabel } from '@/lib/utils'
import type { ConnectionSession } from '@/types'

export function WorkspaceView() {
  const app = useApp()
  const { t } = useTranslation()
  const workspace = app.workspace
  const [status, setStatus] = useState(workspace?.status || 'connecting')
  const sshMessages = useMemo(
    () => ({
      connecting: t('workspace.connecting'),
      connected: t('workspace.connected'),
      disconnected: t('workspace.disconnected'),
    }),
    [t]
  )
  const rdpMessages = useMemo(
    () => ({
      missingGuacamole: t('workspace.missingGuacamole'),
      rdpFailed: t('workspace.rdpFailed'),
      clipboardPrompt: t('workspace.clipboardPrompt'),
      clipboardSent: t('workspace.clipboardSent'),
      fileSent: t('workspace.fileSent'),
    }),
    [t]
  )

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
    <div className='grid min-h-svh grid-rows-[52px_minmax(0,1fr)] bg-background text-foreground'>
      <div className='flex min-w-0 items-center justify-between gap-3 border-b border-border bg-background/95 px-3 backdrop-blur-xl max-md:h-auto max-md:flex-col max-md:items-start max-md:py-3'>
        <div className='flex min-w-0 items-center gap-2'>
          <strong>{workspace.session.protocol.toUpperCase()}</strong>
          <span className='truncate text-muted-foreground'>{server?.name || workspace.session.server_id}</span>
          <Badge tone={status === 'connected' ? 'success' : 'neutral'}>{statusLabel(status)}</Badge>
          {workspace.session.protocol === 'rdp' ? <Badge tone='danger'>{t('workspace.recordingOn')}</Badge> : null}
        </div>
        <div className='flex flex-wrap gap-2'>
          {workspace.type === 'rdp' ? (
            <>
              <Button variant='outline' onClick={() => window.dispatchEvent(new Event('servermanager:rdp-clipboard'))}><Clipboard className='size-4' />{t('workspace.clipboard')}</Button>
              <Button variant='outline' onClick={() => window.dispatchEvent(new Event('servermanager:rdp-upload'))}><Upload className='size-4' />{t('workspace.uploadFile')}</Button>
            </>
          ) : null}
          <Button variant='outline' onClick={() => void leave()}>{t('workspace.returnConsole')}</Button>
          <Button variant='destructive' onClick={() => void close()}><Power className='size-4' />{t('workspace.disconnect')}</Button>
        </div>
      </div>
      {workspace.type === 'ssh' ? (
        <SSHWorkspace
          session={workspace.session}
          setStatus={setStatus}
          messages={sshMessages}
        />
      ) : (
        <RDPWorkspace
          session={workspace.session}
          setStatus={setStatus}
          showToast={app.showToast}
          messages={rdpMessages}
        />
      )}
    </div>
  )
}

function SSHWorkspace({
  session,
  setStatus,
  messages,
}: {
  session: ConnectionSession
  setStatus: (status: string) => void
  messages: { connecting: string; connected: string; disconnected: string }
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!containerRef.current) return
    const styles = getComputedStyle(document.body)
    const isDark = document.documentElement.classList.contains('dark')
    const background = styles.getPropertyValue(isDark ? '--background' : '--foreground').trim()
    const foreground = styles.getPropertyValue(isDark ? '--foreground' : '--background').trim()
    const term = new Terminal({
      cursorBlink: true,
      convertEol: true,
      fontFamily: 'Cascadia Mono, JetBrains Mono, Consolas, monospace',
      fontSize: 13,
      theme: { background, foreground },
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)
    fit.fit()
    term.focus()
    term.write(`${messages.connecting}\r\n`)

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
        term.write(`${messages.connected}\r\n`)
      }
      if (msg.type === 'stdout' || msg.type === 'stderr') term.write(base64ToText(msg.data).replaceAll('\n', '\r\n'))
      if (msg.type === 'error') term.write(`\r\n[error] ${msg.data}\r\n`)
    }
    socket.onclose = () => {
      setStatus('disconnected')
      term.write(`\r\n[${messages.disconnected}]\r\n`)
    }

    return () => {
      resizeObserver.disconnect()
      socket.close()
      term.dispose()
    }
  }, [messages.connected, messages.connecting, messages.disconnected, session.id, setStatus])

  return <div ref={containerRef} className='h-[calc(100vh-52px)] bg-background p-3 max-md:h-[calc(100vh-120px)]' />
}

function RDPWorkspace({
  session,
  setStatus,
  showToast,
  messages,
}: {
  session: ConnectionSession
  setStatus: (status: string) => void
  showToast: (message: string) => void
  messages: {
    missingGuacamole: string
    rdpFailed: string
    clipboardPrompt: string
    clipboardSent: string
    fileSent: string
  }
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const clientRef = useRef<any>(null)

  useEffect(() => {
    const container = containerRef.current
    const Guacamole = window.Guacamole
    if (!container) return
    if (!Guacamole) {
      const message = document.createElement('div')
      message.style.cssText = 'margin:20px;padding:16px;border:1px solid var(--border);border-radius:var(--radius);background:var(--card);color:var(--card-foreground)'
      message.textContent = messages.missingGuacamole
      container.replaceChildren(message)
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
    client.onerror = (err: { message?: string }) => showToast(err.message || messages.rdpFailed)

    const onClipboard = () => {
      const text = window.prompt(messages.clipboardPrompt)
      if (text == null) return
      const stream = client.createClipboardStream('text/plain')
      const writer = new Guacamole.StringWriter(stream)
      writer.sendText(text)
      writer.sendEnd()
      showToast(messages.clipboardSent)
    }
    const onUpload = () => {
      const input = document.createElement('input')
      input.type = 'file'
      input.onchange = () => {
        const file = input.files?.[0]
        if (!file) return
        const stream = client.createFileStream(file.type || 'application/octet-stream', file.name)
        const writer = new Guacamole.BlobWriter(stream)
        writer.oncomplete = () => showToast(messages.fileSent)
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
  }, [messages, session.id, setStatus, showToast])

  return <div ref={containerRef} className='h-[calc(100vh-52px)] overflow-hidden bg-background max-md:h-[calc(100vh-120px)]' />
}
