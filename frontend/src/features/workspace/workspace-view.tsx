import { FitAddon } from '@xterm/addon-fit'
import { useQuery } from '@tanstack/react-query'
import { Terminal } from '@xterm/xterm'
import { Clipboard, Code2, Power, Upload } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DialogShell } from '@/components/ui/dialog'
import { Field, Select, Textarea } from '@/components/ui/field'
import { apiRequest } from '@/lib/api'
import { base64ToText, textToBase64 } from '@/lib/codec'
import { statusLabel } from '@/lib/utils'
import type { ConnectionSession, PlatformItem } from '@/types'

interface AccessCommandSnippetsResponse {
  items?: PlatformItem[]
}

export function WorkspaceView() {
  const app = useApp()
  const { t } = useTranslation()
  const workspace = app.workspace
  const [status, setStatus] = useState(workspace?.status || 'connecting')
  const [selectedSnippetID, setSelectedSnippetID] = useState('')
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
      clipboardDialogDescription: t('workspace.clipboardDialogDescription'),
      clipboardTextLabel: t('workspace.clipboardTextLabel'),
      clipboardTextPlaceholder: t('workspace.clipboardTextPlaceholder'),
      sendClipboard: t('workspace.sendClipboard'),
      cancel: t('cancel'),
      clipboardSent: t('workspace.clipboardSent'),
      fileSent: t('workspace.fileSent'),
    }),
    [t]
  )
  const commandSnippetsQuery = useQuery({
    queryKey: ['access-command-snippets'],
    queryFn: () => apiRequest<AccessCommandSnippetsResponse>('/api/access/command-snippets'),
    enabled: workspace?.type === 'ssh',
    staleTime: 10_000,
  })

  if (!workspace) return null

  const server = app.data.servers.find((item) => item.id === workspace.session.server_id)
  const platformAsset = app.data.platform?.assets?.find((item) => item.id === workspace.session.server_id)
  const commandSnippets = commandSnippetsQuery.data?.items || []
  const selectedSnippet = commandSnippets.find((item) => item.id === selectedSnippetID) || commandSnippets[0]
  const isDesktopWorkspace = workspace.type === 'rdp' || workspace.type === 'vnc'
  const clipboardEnabled = isDesktopWorkspace && workspace.session.clipboard_enabled !== false
  const fileTransferEnabled = workspace.type === 'rdp'
    ? workspace.session.file_transfer_enabled !== false
    : workspace.type === 'vnc' && workspace.session.file_transfer_enabled === true

  const leave = async () => {
    app.setWorkspace(null)
    await app.refresh(true)
  }

  const close = async () => {
    await apiRequest(`/api/connections/${workspace.session.id}/close`, { method: 'POST', body: '{}' })
    app.setWorkspace(null)
    await app.refresh(true)
  }

  const insertCommandSnippet = () => {
    const command = snippetCommand(selectedSnippet)
    if (!command) return
    const payload = snippetAppendNewline(selectedSnippet) ? commandWithEnter(command) : command
    window.dispatchEvent(new CustomEvent('openwebservermanager:ssh-snippet', { detail: { command: payload } }))
    app.showToast(t('workspace.commandSnippetInserted', { defaultValue: 'Command inserted.' }))
  }

  return (
    <div className='grid min-h-svh grid-rows-[52px_minmax(0,1fr)] bg-background text-foreground'>
      <div className='flex min-w-0 items-center justify-between gap-3 border-b border-border bg-background/95 px-3 backdrop-blur-xl max-md:h-auto max-md:flex-col max-md:items-start max-md:py-3'>
        <div className='flex min-w-0 items-center gap-2'>
          <strong>{workspace.session.protocol.toUpperCase()}</strong>
          <span className='truncate text-muted-foreground'>{server?.name || platformAsset?.name || workspace.session.server_id}</span>
          <Badge tone={status === 'connected' ? 'success' : 'neutral'}>{statusLabel(status)}</Badge>
          {workspace.session.recording_path ? <Badge tone='danger'>{t('workspace.recordingOn')}</Badge> : null}
        </div>
        <div className='flex flex-wrap gap-2'>
          {workspace.type === 'ssh' ? (
            <div className='flex min-w-0 gap-2'>
              <Select
                className='w-48 max-w-[52vw]'
                value={selectedSnippet?.id || ''}
                onChange={(event) => setSelectedSnippetID(event.currentTarget.value)}
                disabled={!commandSnippets.length}
                aria-label={t('workspace.commandSnippet', { defaultValue: 'Command snippet' })}
              >
                {commandSnippets.length ? commandSnippets.map((snippet) => (
                  <option key={snippet.id} value={snippet.id}>{snippet.name}</option>
                )) : (
                  <option value=''>{t('workspace.noCommandSnippets', { defaultValue: 'No snippets' })}</option>
                )}
              </Select>
              <Button variant='outline' onClick={insertCommandSnippet} disabled={status !== 'connected' || !snippetCommand(selectedSnippet)}>
                <Code2 className='size-4' />
                {t('workspace.insertSnippet', { defaultValue: 'Insert' })}
              </Button>
            </div>
          ) : null}
          {isDesktopWorkspace ? (
            <>
              {clipboardEnabled ? (
                <Button variant='outline' onClick={() => window.dispatchEvent(new Event('openwebservermanager:desktop-clipboard'))}><Clipboard className='size-4' />{t('workspace.clipboard')}</Button>
              ) : null}
              {fileTransferEnabled ? (
                <Button variant='outline' onClick={() => window.dispatchEvent(new Event('openwebservermanager:desktop-upload'))}><Upload className='size-4' />{t('workspace.uploadFile')}</Button>
              ) : null}
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
          clipboardEnabled={clipboardEnabled}
          fileTransferEnabled={fileTransferEnabled}
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
    const sendStdin = (data: string) => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'stdin', data: textToBase64(data) }))
      }
    }
    const sendResize = () => {
      fit.fit()
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
      }
    }
    const resizeObserver = new ResizeObserver(sendResize)
    resizeObserver.observe(containerRef.current)

    term.onData((data) => {
      sendStdin(data)
    })
    const onSnippet = (event: Event) => {
      const command = (event as CustomEvent<{ command?: string }>).detail?.command
      if (!command) return
      sendStdin(command)
      term.focus()
    }
    window.addEventListener('openwebservermanager:ssh-snippet', onSnippet)

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
      window.removeEventListener('openwebservermanager:ssh-snippet', onSnippet)
      socket.close()
      term.dispose()
    }
  }, [messages.connected, messages.connecting, messages.disconnected, session.id, setStatus])

  return <div ref={containerRef} className='h-[calc(100vh-52px)] bg-background p-3 max-md:h-[calc(100vh-120px)]' />
}

function snippetCommand(snippet: PlatformItem | undefined): string {
  if (!snippet) return ''
  for (const key of ['command', 'content', 'value', 'text']) {
    const value = snippet.metadata?.[key]
    if (typeof value === 'string' && value.trim()) return value
  }
  return snippet.description || ''
}

function snippetAppendNewline(snippet: PlatformItem | undefined): boolean {
  if (!snippet) return false
  for (const key of ['append_newline', 'appendNewline', 'auto_enter', 'autoEnter', 'execute']) {
    const value = snippet.metadata?.[key]
    if (typeof value === 'boolean') return value
    if (typeof value === 'string') return ['true', '1', 'yes', 'enabled'].includes(value.trim().toLowerCase())
  }
  return false
}

function commandWithEnter(command: string): string {
  return command.endsWith('\r') || command.endsWith('\n') ? command : `${command}\r`
}

function RDPWorkspace({
  session,
  setStatus,
  showToast,
  messages,
  clipboardEnabled,
  fileTransferEnabled,
}: {
  session: ConnectionSession
  setStatus: (status: string) => void
  showToast: (message: string) => void
  clipboardEnabled: boolean
  fileTransferEnabled: boolean
  messages: {
    missingGuacamole: string
    rdpFailed: string
    clipboardPrompt: string
    clipboardDialogDescription: string
    clipboardTextLabel: string
    clipboardTextPlaceholder: string
    sendClipboard: string
    cancel: string
    clipboardSent: string
    fileSent: string
  }
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const clientRef = useRef<any>(null)
  const [clipboardDialogOpen, setClipboardDialogOpen] = useState(false)
  const [clipboardText, setClipboardText] = useState('')

  const sendClipboardText = () => {
    const client = clientRef.current
    const Guacamole = window.Guacamole
    if (!client || !Guacamole) {
      showToast(messages.rdpFailed)
      return
    }
    const stream = client.createClipboardStream('text/plain')
    const writer = new Guacamole.StringWriter(stream)
    writer.sendText(clipboardText)
    writer.sendEnd()
    setClipboardDialogOpen(false)
    setClipboardText('')
    showToast(messages.clipboardSent)
  }

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
    const dpi = session.dpi || 96
    const tunnel = new Guacamole.WebSocketTunnel(`${proto}://${window.location.host}/api/connections/${session.protocol}/${session.id}/tunnel?width=${width}&height=${height}&dpi=${dpi}`)
    const client = new Guacamole.Client(tunnel)
    clientRef.current = client
    const display = client.getDisplay().getElement()
    display.tabIndex = 0
    display.style.position = 'relative'
    display.style.zIndex = '0'
    display.style.isolation = 'isolate'
    display.style.backgroundColor = '#000'
    display.style.outline = 'none'
    display.style.userSelect = 'none'
    display.style.touchAction = 'none'
    container.replaceChildren(display)
    client.connect('')

    const focusDisplay = () => display.focus({ preventScroll: true })
    const pressedKeysyms = new Set<number>()
    const releaseKeysyms = (keysyms: Iterable<number>) => {
      for (const keysym of keysyms) {
        if (!pressedKeysyms.delete(keysym)) continue
        client.sendKeyEvent(0, keysym)
      }
    }
    const preventBrowserPointerAction = (event: Event) => {
      event.preventDefault()
      event.stopPropagation()
    }
    const preventBrowserKeyboardAction = (event: KeyboardEvent) => {
      if (event.altKey || event.ctrlKey || event.metaKey || event.key === 'Alt' || event.key === 'Control' || event.key === 'Meta') {
        event.preventDefault()
      }
    }
    const mouse = new Guacamole.Mouse(display)
    const sendMouseState = (mouseState: unknown) => client.sendMouseState(mouseState, true)
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = mouse.onmouseout = sendMouseState
    const keyboard = new Guacamole.Keyboard(display)
    keyboard.onkeydown = (keysym: number) => {
      pressedKeysyms.add(keysym)
      client.sendKeyEvent(1, keysym)
    }
    keyboard.onkeyup = (keysym: number) => {
      pressedKeysyms.delete(keysym)
      client.sendKeyEvent(0, keysym)
    }
    focusDisplay()
    client.onstatechange = (stateCode: number) => {
      if (stateCode === 3) setStatus('connected')
      if (stateCode === 5) setStatus('disconnected')
    }
    client.onerror = (err: { message?: string }) => {
      setStatus('disconnected')
      showToast(err.message || messages.rdpFailed)
    }

    const onClipboard = () => {
      setClipboardText('')
      setClipboardDialogOpen(true)
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
    const releaseInputState = () => {
      mouse.reset?.()
      keyboard.reset?.()
      releaseKeysyms(Array.from(pressedKeysyms))
    }
    const releaseStaleModifiers = (event: MouseEvent) => {
      if (!event.shiftKey) releaseKeysyms([65505, 65506])
      if (!event.ctrlKey) releaseKeysyms([65507, 65508])
      if (!event.altKey) releaseKeysyms([65513, 65514, 65027])
      if (!event.metaKey) releaseKeysyms([65511, 65512, 65515, 65516])
    }
    const onDocumentPointerDown = (event: PointerEvent) => {
      if (event.target instanceof Node && !display.contains(event.target)) {
        releaseInputState()
      }
    }
    const onWindowKeyUp = (event: KeyboardEvent) => {
      if (!(event.target instanceof Node) || !display.contains(event.target)) {
        releaseInputState()
      }
    }
    const onBeforeUnload = () => client.disconnect()
    display.addEventListener('mousedown', releaseStaleModifiers, true)
    display.addEventListener('mousedown', focusDisplay, true)
    display.addEventListener('blur', releaseInputState)
    display.addEventListener('keydown', preventBrowserKeyboardAction, true)
    display.addEventListener('keyup', preventBrowserKeyboardAction, true)
    display.addEventListener('contextmenu', preventBrowserPointerAction, true)
    display.addEventListener('dragstart', preventBrowserPointerAction, true)
    document.addEventListener('pointerdown', onDocumentPointerDown, true)
    if (clipboardEnabled) window.addEventListener('openwebservermanager:desktop-clipboard', onClipboard)
    if (fileTransferEnabled) window.addEventListener('openwebservermanager:desktop-upload', onUpload)
    window.addEventListener('resize', onResize)
    window.addEventListener('keyup', onWindowKeyUp)
    window.addEventListener('blur', releaseInputState)
    document.addEventListener('visibilitychange', releaseInputState)
    window.addEventListener('beforeunload', onBeforeUnload)

    return () => {
      display.removeEventListener('mousedown', releaseStaleModifiers, true)
      display.removeEventListener('mousedown', focusDisplay, true)
      display.removeEventListener('blur', releaseInputState)
      display.removeEventListener('keydown', preventBrowserKeyboardAction, true)
      display.removeEventListener('keyup', preventBrowserKeyboardAction, true)
      display.removeEventListener('contextmenu', preventBrowserPointerAction, true)
      display.removeEventListener('dragstart', preventBrowserPointerAction, true)
      document.removeEventListener('pointerdown', onDocumentPointerDown, true)
      if (clipboardEnabled) window.removeEventListener('openwebservermanager:desktop-clipboard', onClipboard)
      if (fileTransferEnabled) window.removeEventListener('openwebservermanager:desktop-upload', onUpload)
      window.removeEventListener('resize', onResize)
      window.removeEventListener('keyup', onWindowKeyUp)
      window.removeEventListener('blur', releaseInputState)
      document.removeEventListener('visibilitychange', releaseInputState)
      window.removeEventListener('beforeunload', onBeforeUnload)
      releaseInputState()
      client.disconnect()
      clientRef.current = null
      container.innerHTML = ''
    }
  }, [clipboardEnabled, fileTransferEnabled, messages, session.dpi, session.id, session.protocol, setStatus, showToast])

  const watermarkText = session.watermark_enabled ? session.watermark_text?.trim() : ''

  return (
    <>
      <div className='relative h-[calc(100vh-52px)] overflow-hidden bg-black max-md:h-[calc(100vh-120px)]'>
        <div ref={containerRef} className='size-full' />
        {watermarkText ? (
          <div
            className='pointer-events-none absolute inset-0 z-10 grid place-items-center text-center font-semibold uppercase tracking-wider'
            style={{
              color: session.watermark_color || 'rgba(255,255,255,0.18)',
              fontSize: `${session.watermark_font_size || 28}px`,
            }}
          >
            {watermarkText}
          </div>
        ) : null}
      </div>
      <DialogShell
        open={clipboardDialogOpen}
        onOpenChange={setClipboardDialogOpen}
        compact
        title={messages.clipboardPrompt}
        description={messages.clipboardDialogDescription}
      >
        <form
          className='grid gap-4'
          onSubmit={(event) => {
            event.preventDefault()
            sendClipboardText()
          }}
        >
          <Field label={messages.clipboardTextLabel}>
            <Textarea
              autoFocus
              className='min-h-36'
              value={clipboardText}
              onChange={(event) => setClipboardText(event.currentTarget.value)}
              placeholder={messages.clipboardTextPlaceholder}
            />
          </Field>
          <div className='flex justify-end gap-2'>
            <Button type='button' variant='outline' onClick={() => setClipboardDialogOpen(false)}>
              {messages.cancel}
            </Button>
            <Button type='submit' variant='primary'>
              <Clipboard className='size-4' />
              {messages.sendClipboard}
            </Button>
          </div>
        </form>
      </DialogShell>
    </>
  )
}
