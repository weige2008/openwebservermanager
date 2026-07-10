import { FitAddon } from '@xterm/addon-fit'
import { useQuery } from '@tanstack/react-query'
import { Terminal } from '@xterm/xterm'
import { ArrowUp, Clipboard, Code2, Download, FileDown, FolderOpen, Power, RefreshCw, Trash2, Upload } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { DialogShell } from '@/components/ui/dialog'
import { Field, Select, Textarea } from '@/components/ui/field'
import { isAccessMFARequiredError, useAccessMFADialog } from '@/features/access/access-mfa'
import { ApiError, apiRequest } from '@/lib/api'
import { base64ToText, textToBase64 } from '@/lib/codec'
import { formatDate, statusLabel } from '@/lib/utils'
import type { ConnectionSession, PlatformItem } from '@/types'

interface AccessCommandSnippetsResponse {
  items?: PlatformItem[]
}

interface DesktopDriveEntry {
  name: string
  path: string
  is_dir: boolean
  size: number
  modified: string
}

interface DesktopDriveResponse {
  path: string
  entries: DesktopDriveEntry[]
}

interface FileWorkspaceMessages {
  sessionFiles: string
  sessionFilesDescription: string
  refreshFiles: string
  parentFolder: string
  emptyFiles: string
  openFolder: string
  downloadFile: string
  deleteFile: string
  fileDeleted: string
  fileUploaded: string
  uploadSessionFile: string
  fileListFailed: string
  pathLabel: string
  modifiedLabel: string
  sizeLabel: string
}

export function WorkspaceView() {
  const app = useApp()
  const { t } = useTranslation()
  const workspace = app.workspace
  const [status, setStatus] = useState(workspace?.status || 'connecting')
  const [closing, setClosing] = useState(false)
  const [reconnecting, setReconnecting] = useState(false)
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
      clipboardTitle: t('workspace.clipboard'),
      clipboardPrompt: t('workspace.clipboardPrompt'),
      clipboardDialogDescription: t('workspace.clipboardDialogDescription'),
      clipboardTextLabel: t('workspace.clipboardTextLabel'),
      clipboardTextPlaceholder: t('workspace.clipboardTextPlaceholder'),
      sendClipboard: t('workspace.sendClipboard'),
      cancel: t('cancel'),
      remoteClipboard: t('workspace.remoteClipboard', { defaultValue: 'Remote clipboard' }),
      remoteClipboardDescription: t('workspace.remoteClipboardDescription', { defaultValue: 'The latest text copied inside the remote desktop.' }),
      remoteClipboardEmpty: t('workspace.remoteClipboardEmpty', { defaultValue: 'No remote clipboard text received yet.' }),
      copyRemoteClipboard: t('workspace.copyRemoteClipboard', { defaultValue: 'Copy locally' }),
      remoteClipboardReceived: t('workspace.remoteClipboardReceived', { defaultValue: 'Remote clipboard received.' }),
      remoteClipboardCopied: t('workspace.remoteClipboardCopied', { defaultValue: 'Remote clipboard copied.' }),
      remoteClipboardCopyFailed: t('workspace.remoteClipboardCopyFailed', { defaultValue: 'Unable to copy clipboard text in this browser.' }),
      clipboardSent: t('workspace.clipboardSent'),
      fileSent: t('workspace.fileSent'),
      sessionFiles: t('workspace.sessionFiles', { defaultValue: 'Session files' }),
      sessionFilesDescription: t('workspace.sessionFilesDescription', { defaultValue: 'Browse files exposed through the session drive for this desktop connection.' }),
      refreshFiles: t('workspace.refreshFiles', { defaultValue: 'Refresh' }),
      parentFolder: t('workspace.parentFolder', { defaultValue: 'Parent' }),
      emptyFiles: t('workspace.emptyFiles', { defaultValue: 'No files in this folder.' }),
      openFolder: t('workspace.openFolder', { defaultValue: 'Open' }),
      downloadFile: t('workspace.downloadFile', { defaultValue: 'Download' }),
      deleteFile: t('workspace.deleteFile', { defaultValue: 'Delete' }),
      fileDeleted: t('workspace.fileDeleted', { defaultValue: 'File deleted.' }),
      fileUploaded: t('workspace.fileUploaded', { defaultValue: 'File uploaded.' }),
      uploadSessionFile: t('workspace.uploadSessionFile', { defaultValue: 'Upload here' }),
      fileListFailed: t('workspace.fileListFailed', { defaultValue: 'Unable to load session files.' }),
      pathLabel: t('workspace.pathLabel', { defaultValue: 'Path' }),
      modifiedLabel: t('workspace.modifiedLabel', { defaultValue: 'Modified' }),
      sizeLabel: t('workspace.sizeLabel', { defaultValue: 'Size' }),
    }),
    [t]
  )
  const sshFileMessages = useMemo(
    () => ({
      ...rdpMessages,
      sessionFilesDescription: t('workspace.sshFilesDescription', { defaultValue: 'Browse files on the remote SSH server through SFTP.' }),
    }),
    [rdpMessages, t]
  )
  const commandSnippetsQuery = useQuery({
    queryKey: ['access-command-snippets'],
    queryFn: () => apiRequest<AccessCommandSnippetsResponse>('/api/access/command-snippets'),
    enabled: workspace?.type === 'ssh',
    staleTime: 10_000,
  })
  const { requestAccessMFACode, accessMFADialog } = useAccessMFADialog()

  if (!workspace) return null

  const server = app.data.servers.find((item) => item.id === workspace.session.server_id)
  const platformAsset = app.data.platform?.assets?.find((item) => item.id === workspace.session.server_id)
  const commandSnippets = commandSnippetsQuery.data?.items || []
  const selectedSnippet = commandSnippets.find((item) => item.id === selectedSnippetID) || commandSnippets[0]
  const isDesktopWorkspace = workspace.type === 'rdp' || workspace.type === 'vnc'
  const clipboardEnabled = isDesktopWorkspace && workspace.session.clipboard_enabled !== false
  const sshFileTransferEnabled = workspace.type === 'ssh' && workspace.session.file_transfer_enabled !== false
  const fileTransferEnabled = workspace.type === 'rdp'
    ? workspace.session.file_transfer_enabled !== false
    : workspace.type === 'vnc' && workspace.session.file_transfer_enabled === true
  const watermarkText = workspace.session.watermark_enabled
    ? resolveWorkspaceWatermark(
      workspace.session.watermark_text || '',
      app.auth?.username || workspace.session.user_id,
      server?.name || platformAsset?.name || workspace.session.server_id
    )
    : ''

  const leave = async () => {
    app.setWorkspace(null)
    await app.refresh(true)
  }

  const close = async () => {
    if (closing) return
    setClosing(true)
    try {
      await apiRequest(`/api/connections/${workspace.session.id}/close`, { method: 'POST', body: '{}' })
      app.setWorkspace(null)
      await app.refresh(true)
    } catch (error) {
      if (error instanceof ApiError && (error.status === 404 || error.status === 409)) {
        app.setWorkspace(null)
        await app.refresh(true)
        return
      }
      app.handleApiError(error)
    } finally {
      setClosing(false)
    }
  }

  const reconnect = async () => {
    if (reconnecting) return
    setReconnecting(true)
    try {
      const protocol = workspace.type
      const asset = app.data.platform?.assets?.find((item) => item.id === workspace.session.server_id)
      const dimensions = protocol === 'ssh'
        ? { cols: workspace.session.width || 120, rows: workspace.session.height || 32, term: 'xterm-256color' }
        : {
          width: Math.max(1024, window.innerWidth),
          height: Math.max(680, window.innerHeight - 52),
          dpi: workspace.session.dpi || 96,
          recording_enabled: Boolean(workspace.session.recording_path),
        }
      const payload = {
        ...dimensions,
        credential_id: workspace.session.credential_id,
        reconnect_from: workspace.session.id,
        ...(asset ? {} : { server_id: workspace.session.server_id }),
      }
      const endpoint = asset ? `/api/access/${protocol}/${asset.id}` : `/api/connections/${protocol}`
      const createSession = (mfaCode = '') => apiRequest<ConnectionSession>(endpoint, {
        method: 'POST',
        body: JSON.stringify(mfaCode ? { ...payload, mfa_code: mfaCode } : payload),
      })
      let session: ConnectionSession
      try {
        session = await createSession()
      } catch (error) {
        if (!isAccessMFARequiredError(error)) throw error
        const mfaCode = await requestAccessMFACode()
        if (!mfaCode) return
        session = await createSession(mfaCode)
      }
      setStatus('connecting')
      app.setWorkspace({ type: protocol, session, status: 'connecting' })
      app.showToast(t('workspace.reconnected', { defaultValue: 'Reconnect session created.' }))
    } catch (error) {
      app.handleApiError(error)
    } finally {
      setReconnecting(false)
    }
  }

  const insertCommandSnippet = () => {
    const command = snippetCommand(selectedSnippet)
    if (!command) return
    const payload = snippetAppendNewline(selectedSnippet) ? commandWithEnter(command) : command
    window.dispatchEvent(new CustomEvent('openwebservermanager:ssh-snippet', { detail: { command: payload } }))
    app.showToast(t('workspace.commandSnippetInserted', { defaultValue: 'Command inserted.' }))
  }

  return (
    <>
      <div className='grid h-svh grid-rows-[52px_minmax(0,1fr)] bg-background text-foreground max-md:grid-rows-[auto_minmax(0,1fr)]'>
      <div className='flex min-w-0 items-center justify-between gap-3 border-b border-border bg-background/95 px-3 backdrop-blur-xl max-md:h-auto max-md:flex-col max-md:items-start max-md:py-3'>
        <div className='flex min-w-0 items-center gap-2'>
          <strong>{workspace.session.protocol.toUpperCase()}</strong>
          <span className='truncate text-muted-foreground'>{server?.name || platformAsset?.name || workspace.session.server_id}</span>
          <Badge tone={status === 'connected' ? 'success' : 'neutral'}>{statusLabel(status)}</Badge>
          {workspace.session.recording_path ? <Badge tone='danger'>{t('workspace.recordingOn')}</Badge> : null}
        </div>
        <div className='flex flex-wrap gap-2'>
          {workspace.type === 'ssh' ? (
            <>
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
              {sshFileTransferEnabled ? (
                <>
                  <Button variant='outline' onClick={() => window.dispatchEvent(new Event('openwebservermanager:ssh-files'))}><FolderOpen className='size-4' />{rdpMessages.sessionFiles}</Button>
                  <Button variant='outline' onClick={() => window.dispatchEvent(new Event('openwebservermanager:ssh-upload'))}><Upload className='size-4' />{t('workspace.uploadFile')}</Button>
                </>
              ) : null}
            </>
          ) : null}
          {isDesktopWorkspace ? (
            <>
              {clipboardEnabled ? (
                <Button variant='outline' onClick={() => window.dispatchEvent(new Event('openwebservermanager:desktop-clipboard'))}><Clipboard className='size-4' />{t('workspace.clipboard')}</Button>
              ) : null}
              {fileTransferEnabled ? (
                <>
                  <Button variant='outline' onClick={() => window.dispatchEvent(new Event('openwebservermanager:desktop-files'))}><FolderOpen className='size-4' />{t('workspace.sessionFiles', { defaultValue: 'Session files' })}</Button>
                  <Button variant='outline' onClick={() => window.dispatchEvent(new Event('openwebservermanager:desktop-upload'))}><Upload className='size-4' />{t('workspace.uploadFile')}</Button>
                </>
              ) : null}
            </>
          ) : null}
          {status === 'disconnected' ? (
            <>
              <Button variant='primary' onClick={() => void reconnect()} disabled={reconnecting}>
                <RefreshCw className={reconnecting ? 'size-4 animate-spin' : 'size-4'} />
                {reconnecting ? t('workspace.reconnecting', { defaultValue: 'Reconnecting...' }) : t('workspace.reconnect', { defaultValue: 'Reconnect' })}
              </Button>
              <Button variant='outline' onClick={() => void leave()} disabled={reconnecting}>{t('workspace.returnConsole')}</Button>
            </>
          ) : null}
          <Button variant='destructive' onClick={() => void close()} disabled={closing || status === 'disconnected'}>
            <Power className='size-4' />
            {closing ? t('workspace.disconnecting', { defaultValue: 'Disconnecting...' }) : t('workspace.disconnect')}
          </Button>
        </div>
      </div>
      {workspace.type === 'ssh' ? (
        <SSHWorkspace
          session={workspace.session}
          setStatus={setStatus}
          messages={sshMessages}
          fileMessages={sshFileMessages}
          fileTransferEnabled={sshFileTransferEnabled}
          watermarkText={watermarkText}
        />
      ) : (
        <RDPWorkspace
          session={workspace.session}
          setStatus={setStatus}
          showToast={app.showToast}
          messages={rdpMessages}
          clipboardEnabled={clipboardEnabled}
          fileTransferEnabled={fileTransferEnabled}
          watermarkText={watermarkText}
        />
      )}
      </div>
      {accessMFADialog}
    </>
  )
}

function SSHWorkspace({
  session,
  setStatus,
  messages,
  fileMessages,
  fileTransferEnabled,
  watermarkText,
}: {
  session: ConnectionSession
  setStatus: (status: string) => void
  messages: { connecting: string; connected: string; disconnected: string }
  fileMessages: FileWorkspaceMessages
  fileTransferEnabled: boolean
  watermarkText: string
}) {
  const app = useApp()
  const containerRef = useRef<HTMLDivElement | null>(null)
  const [filesOpen, setFilesOpen] = useState(false)
  const [filePath, setFilePath] = useState('')
  const [uploading, setUploading] = useState(false)
  const filesQuery = useQuery({
    queryKey: ['ssh-files', session.id, filePath],
    queryFn: () => apiRequest<DesktopDriveResponse>(`/api/connections/${session.id}/sftp?path=${encodeURIComponent(filePath)}`),
    enabled: fileTransferEnabled && filesOpen,
    staleTime: 2_000,
  })
  const currentPath = filesQuery.data?.path || filePath
  const refetchFiles = filesQuery.refetch
  const handleApiError = app.handleApiError
  const showToast = app.showToast

  const openEntry = (entry: DesktopDriveEntry) => {
    if (entry.is_dir) setFilePath(entry.path)
  }

  const goParent = () => {
    setFilePath(parentRemotePath(currentPath))
  }

  const downloadEntry = async (entry: DesktopDriveEntry) => {
    try {
      await downloadSSHFile(session.id, entry)
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const deleteEntry = async (entry: DesktopDriveEntry) => {
    if (entry.is_dir) return
    try {
      await apiRequest(`/api/connections/${session.id}/sftp?path=${encodeURIComponent(entry.path)}`, { method: 'DELETE' })
      app.showToast(fileMessages.fileDeleted)
      await filesQuery.refetch()
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const uploadFile = useCallback(() => {
    const input = document.createElement('input')
    input.type = 'file'
    input.onchange = () => {
      const file = input.files?.[0]
      if (!file) return
      setUploading(true)
      void uploadSSHFile(session.id, currentPath, file)
        .then(async () => {
          showToast(fileMessages.fileUploaded)
          if (filesOpen) await refetchFiles()
        })
        .catch(handleApiError)
        .finally(() => setUploading(false))
    }
    input.click()
  }, [currentPath, fileMessages.fileUploaded, filesOpen, handleApiError, refetchFiles, session.id, showToast])

  useEffect(() => {
    if (!fileTransferEnabled) return
    const onFiles = () => setFilesOpen(true)
    const onUpload = () => uploadFile()
    window.addEventListener('openwebservermanager:ssh-files', onFiles)
    window.addEventListener('openwebservermanager:ssh-upload', onUpload)
    return () => {
      window.removeEventListener('openwebservermanager:ssh-files', onFiles)
      window.removeEventListener('openwebservermanager:ssh-upload', onUpload)
    }
  }, [fileTransferEnabled, uploadFile])

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

  return (
    <>
      <div className='relative min-h-0 overflow-hidden bg-background'>
        <div ref={containerRef} className='size-full p-3' />
        {watermarkText ? (
          <div
            className='pointer-events-none absolute inset-0 z-10 grid place-items-center text-center font-semibold uppercase'
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
        open={filesOpen}
        onOpenChange={setFilesOpen}
        title={fileMessages.sessionFiles}
        description={fileMessages.sessionFilesDescription}
      >
        <div className='grid gap-3'>
          <div className='flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-muted/30 px-3 py-2'>
            <div className='min-w-0 text-xs text-muted-foreground'>
              <span className='font-medium text-foreground'>{fileMessages.pathLabel}: </span>
              <span className='break-all'>{currentPath || '/'}</span>
            </div>
            <div className='flex gap-2'>
              <Button size='sm' variant='outline' onClick={uploadFile} disabled={uploading}>
                <Upload className='size-3.5' />
                {fileMessages.uploadSessionFile}
              </Button>
              <Button size='sm' variant='outline' onClick={goParent} disabled={!currentPath || currentPath === '/'}>
                <ArrowUp className='size-3.5' />
                {fileMessages.parentFolder}
              </Button>
              <Button size='sm' variant='outline' onClick={() => void filesQuery.refetch()}>
                <RefreshCw className='size-3.5' />
                {fileMessages.refreshFiles}
              </Button>
            </div>
          </div>
          {filesQuery.isError ? (
            <div className='rounded-lg border border-destructive/20 bg-destructive/10 px-3 py-2 text-sm text-destructive'>{fileMessages.fileListFailed}</div>
          ) : null}
          <div className='max-h-[50vh] overflow-auto rounded-lg border border-border'>
            <div className='grid grid-cols-[minmax(0,1fr)_7rem_10rem_10rem] items-center gap-2 border-b border-border bg-muted/40 px-3 py-2 text-xs font-medium text-muted-foreground max-md:grid-cols-[minmax(0,1fr)_auto]'>
              <span>{fileMessages.sessionFiles}</span>
              <span className='max-md:hidden'>{fileMessages.sizeLabel}</span>
              <span className='max-md:hidden'>{fileMessages.modifiedLabel}</span>
              <span className='text-right'>{fileMessages.openFolder}</span>
            </div>
            {filesQuery.isLoading ? (
              <div className='px-3 py-8 text-center text-sm text-muted-foreground'>{fileMessages.refreshFiles}...</div>
            ) : filesQuery.data?.entries?.length ? (
              filesQuery.data.entries.map((entry) => (
                <div key={entry.path} className='grid grid-cols-[minmax(0,1fr)_7rem_10rem_10rem] items-center gap-2 border-b border-border/60 px-3 py-2 text-sm last:border-0 max-md:grid-cols-[minmax(0,1fr)_auto]'>
                  <button
                    type='button'
                    className='min-w-0 truncate text-left font-medium hover:text-primary disabled:hover:text-foreground'
                    disabled={!entry.is_dir}
                    onClick={() => openEntry(entry)}
                  >
                    {entry.is_dir ? <FolderOpen className='mr-2 inline size-4 align-[-2px]' /> : <FileDown className='mr-2 inline size-4 align-[-2px]' />}
                    {entry.name}
                  </button>
                  <span className='text-xs text-muted-foreground max-md:hidden'>{entry.is_dir ? '-' : formatBytes(entry.size)}</span>
                  <span className='truncate text-xs text-muted-foreground max-md:hidden'>{formatDate(entry.modified)}</span>
                  <span className='flex justify-end gap-1'>
                    {entry.is_dir ? (
                      <Button size='icon-sm' variant='ghost' onClick={() => openEntry(entry)} aria-label={fileMessages.openFolder}>
                        <FolderOpen className='size-4' />
                      </Button>
                    ) : (
                      <>
                        <Button size='icon-sm' variant='ghost' onClick={() => void downloadEntry(entry)} aria-label={fileMessages.downloadFile}>
                          <Download className='size-4' />
                        </Button>
                        <Button size='icon-sm' variant='ghost' onClick={() => void deleteEntry(entry)} aria-label={fileMessages.deleteFile}>
                          <Trash2 className='size-4 text-destructive' />
                        </Button>
                      </>
                    )}
                  </span>
                </div>
              ))
            ) : (
              <div className='px-3 py-8 text-center text-sm text-muted-foreground'>{fileMessages.emptyFiles}</div>
            )}
          </div>
        </div>
      </DialogShell>
    </>
  )
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
  watermarkText,
}: {
  session: ConnectionSession
  setStatus: (status: string) => void
  showToast: (message: string) => void
  clipboardEnabled: boolean
  fileTransferEnabled: boolean
  watermarkText: string
  messages: {
    missingGuacamole: string
    rdpFailed: string
    clipboardTitle: string
    clipboardPrompt: string
    clipboardDialogDescription: string
    clipboardTextLabel: string
    clipboardTextPlaceholder: string
    sendClipboard: string
    cancel: string
    remoteClipboard: string
    remoteClipboardDescription: string
    remoteClipboardEmpty: string
    copyRemoteClipboard: string
    remoteClipboardReceived: string
    remoteClipboardCopied: string
    remoteClipboardCopyFailed: string
    clipboardSent: string
    fileSent: string
    sessionFiles: string
    sessionFilesDescription: string
    refreshFiles: string
    parentFolder: string
    emptyFiles: string
    openFolder: string
    downloadFile: string
    deleteFile: string
    fileDeleted: string
    fileUploaded: string
    uploadSessionFile: string
    fileListFailed: string
    pathLabel: string
    modifiedLabel: string
    sizeLabel: string
  }
}) {
  const app = useApp()
  const containerRef = useRef<HTMLDivElement | null>(null)
  const clientRef = useRef<any>(null)
  const [clipboardDialogOpen, setClipboardDialogOpen] = useState(false)
  const [clipboardText, setClipboardText] = useState('')
  const [remoteClipboardText, setRemoteClipboardText] = useState('')
  const [remoteClipboardMimeType, setRemoteClipboardMimeType] = useState('')
  const [remoteClipboardUpdatedAt, setRemoteClipboardUpdatedAt] = useState('')
  const [driveDialogOpen, setDriveDialogOpen] = useState(false)
  const [drivePath, setDrivePath] = useState('')
  const [uploadingDriveFile, setUploadingDriveFile] = useState(false)
  const driveQuery = useQuery({
    queryKey: ['desktop-drive', session.id, drivePath],
    queryFn: () => apiRequest<DesktopDriveResponse>(`/api/connections/${session.id}/drive?path=${encodeURIComponent(drivePath)}`),
    enabled: fileTransferEnabled && driveDialogOpen,
    staleTime: 2_000,
  })

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

  const copyRemoteClipboard = async () => {
    if (!remoteClipboardText) return
    try {
      await copyTextToClipboard(remoteClipboardText)
      showToast(messages.remoteClipboardCopied)
    } catch {
      showToast(messages.remoteClipboardCopyFailed)
    }
  }

  const openDriveEntry = (entry: DesktopDriveEntry) => {
    if (!entry.is_dir) return
    setDrivePath(entry.path === '.' ? '' : entry.path)
  }

  const goParentDriveFolder = () => {
    const normalized = drivePath.replaceAll('\\', '/').replace(/^\/+|\/+$/g, '')
    if (!normalized) return
    const parts = normalized.split('/').filter(Boolean)
    parts.pop()
    setDrivePath(parts.join('/'))
  }

  const downloadDriveEntry = async (entry: DesktopDriveEntry) => {
    try {
      await downloadDesktopDriveFile(session.id, entry)
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const deleteDriveEntry = async (entry: DesktopDriveEntry) => {
    try {
      await apiRequest(`/api/connections/${session.id}/drive?path=${encodeURIComponent(entry.path)}`, { method: 'DELETE' })
      showToast(messages.fileDeleted)
      await driveQuery.refetch()
    } catch (error) {
      app.handleApiError(error)
    }
  }

  const uploadDriveFile = () => {
    const input = document.createElement('input')
    input.type = 'file'
    input.onchange = () => {
      const file = input.files?.[0]
      if (!file) return
      setUploadingDriveFile(true)
      void uploadDesktopDriveFile(session.id, drivePath, file)
        .then(async () => {
          showToast(messages.fileUploaded)
          await driveQuery.refetch()
        })
        .catch(app.handleApiError)
        .finally(() => setUploadingDriveFile(false))
    }
    input.click()
  }

  useEffect(() => {
    if (!fileTransferEnabled) return
    const onFiles = () => setDriveDialogOpen(true)
    window.addEventListener('openwebservermanager:desktop-files', onFiles)
    return () => window.removeEventListener('openwebservermanager:desktop-files', onFiles)
  }, [fileTransferEnabled])

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
    if (clipboardEnabled) {
      client.onclipboard = (stream: unknown, mimeType: string) => {
        const normalizedType = String(mimeType || '').toLowerCase()
        if (normalizedType && !normalizedType.startsWith('text/')) {
          new Guacamole.BlobReader(stream, mimeType || 'application/octet-stream')
          return
        }
        const reader = new Guacamole.StringReader(stream)
        let text = ''
        reader.ontext = (chunk: string) => {
          text += chunk
        }
        reader.onend = () => {
          setRemoteClipboardText(text)
          setRemoteClipboardMimeType(mimeType || 'text/plain')
          setRemoteClipboardUpdatedAt(new Date().toISOString())
          setClipboardDialogOpen(true)
          showToast(messages.remoteClipboardReceived)
        }
      }
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
      client.onclipboard = null
      client.disconnect()
      clientRef.current = null
      container.innerHTML = ''
    }
  }, [clipboardEnabled, fileTransferEnabled, messages, session.dpi, session.id, session.protocol, setStatus, showToast])

  return (
    <>
      <div className='relative min-h-0 overflow-hidden bg-black'>
        <div ref={containerRef} className='size-full' />
        {watermarkText ? (
          <div
            className='pointer-events-none absolute inset-0 z-10 grid place-items-center text-center font-semibold uppercase'
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
        title={messages.clipboardTitle}
        description={messages.clipboardDialogDescription}
      >
        <div className='grid gap-5'>
          <section className='grid gap-2 rounded-lg border border-border bg-muted/20 p-3'>
            <div className='flex flex-wrap items-center justify-between gap-2'>
              <div>
                <div className='text-sm font-medium'>{messages.remoteClipboard}</div>
                <div className='text-xs text-muted-foreground'>{messages.remoteClipboardDescription}</div>
              </div>
              <Button size='sm' variant='outline' onClick={() => void copyRemoteClipboard()} disabled={!remoteClipboardText}>
                <Clipboard className='size-3.5' />
                {messages.copyRemoteClipboard}
              </Button>
            </div>
            {remoteClipboardText ? (
              <>
                <Textarea className='min-h-28 text-xs' value={remoteClipboardText} readOnly />
                <div className='text-xs text-muted-foreground'>
                  {remoteClipboardMimeType || 'text/plain'}
                  {remoteClipboardUpdatedAt ? ` - ${formatDate(remoteClipboardUpdatedAt)}` : ''}
                </div>
              </>
            ) : (
              <div className='rounded-md border border-dashed border-border px-3 py-6 text-center text-sm text-muted-foreground'>{messages.remoteClipboardEmpty}</div>
            )}
          </section>
          <form
            className='grid gap-4'
            onSubmit={(event) => {
              event.preventDefault()
              sendClipboardText()
            }}
          >
            <Field label={messages.clipboardPrompt}>
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
        </div>
      </DialogShell>
      <DialogShell
        open={driveDialogOpen}
        onOpenChange={setDriveDialogOpen}
        title={messages.sessionFiles}
        description={messages.sessionFilesDescription}
      >
        <div className='grid gap-3'>
          <div className='flex flex-wrap items-center justify-between gap-2 rounded-lg border border-border bg-muted/30 px-3 py-2'>
            <div className='min-w-0 text-xs text-muted-foreground'>
              <span className='font-medium text-foreground'>{messages.pathLabel}: </span>
              <span className='break-all'>{driveQuery.data?.path && driveQuery.data.path !== '.' ? driveQuery.data.path : '/'}</span>
            </div>
            <div className='flex gap-2'>
              <Button size='sm' variant='outline' onClick={uploadDriveFile} disabled={uploadingDriveFile}>
                <Upload className='size-3.5' />
                {messages.uploadSessionFile}
              </Button>
              <Button size='sm' variant='outline' onClick={goParentDriveFolder} disabled={!drivePath}>
                <ArrowUp className='size-3.5' />
                {messages.parentFolder}
              </Button>
              <Button size='sm' variant='outline' onClick={() => void driveQuery.refetch()}>
                <RefreshCw className='size-3.5' />
                {messages.refreshFiles}
              </Button>
            </div>
          </div>
          {driveQuery.isError ? (
            <div className='rounded-lg border border-destructive/20 bg-destructive/10 px-3 py-2 text-sm text-destructive'>{messages.fileListFailed}</div>
          ) : null}
          <div className='max-h-[50vh] overflow-auto rounded-lg border border-border'>
            <div className='grid grid-cols-[minmax(0,1fr)_7rem_10rem_10rem] items-center gap-2 border-b border-border bg-muted/40 px-3 py-2 text-xs font-medium text-muted-foreground max-md:grid-cols-[minmax(0,1fr)_7rem]'>
              <span>{messages.sessionFiles}</span>
              <span>{messages.sizeLabel}</span>
              <span className='max-md:hidden'>{messages.modifiedLabel}</span>
              <span className='text-right'>{messages.openFolder}</span>
            </div>
            {driveQuery.isLoading ? (
              <div className='px-3 py-8 text-center text-sm text-muted-foreground'>{messages.refreshFiles}...</div>
            ) : driveQuery.data?.entries?.length ? (
              driveQuery.data.entries.map((entry) => (
                <div key={entry.path} className='grid grid-cols-[minmax(0,1fr)_7rem_10rem_10rem] items-center gap-2 border-b border-border/60 px-3 py-2 text-sm last:border-0 max-md:grid-cols-[minmax(0,1fr)_7rem]'>
                  <button
                    type='button'
                    className='min-w-0 truncate text-left font-medium hover:text-primary disabled:hover:text-foreground'
                    disabled={!entry.is_dir}
                    onClick={() => openDriveEntry(entry)}
                  >
                    {entry.is_dir ? <FolderOpen className='mr-2 inline size-4 align-[-2px]' /> : <FileDown className='mr-2 inline size-4 align-[-2px]' />}
                    {entry.name}
                  </button>
                  <span className='text-xs text-muted-foreground'>{entry.is_dir ? '-' : formatBytes(entry.size)}</span>
                  <span className='truncate text-xs text-muted-foreground max-md:hidden'>{formatDate(entry.modified)}</span>
                  <span className='flex justify-end gap-1'>
                    {entry.is_dir ? (
                      <Button size='icon-sm' variant='ghost' onClick={() => openDriveEntry(entry)} aria-label={messages.openFolder}>
                        <FolderOpen className='size-4' />
                      </Button>
                    ) : (
                      <Button size='icon-sm' variant='ghost' onClick={() => void downloadDriveEntry(entry)} aria-label={messages.downloadFile}>
                        <Download className='size-4' />
                      </Button>
                    )}
                    <Button size='icon-sm' variant='ghost' onClick={() => void deleteDriveEntry(entry)} aria-label={messages.deleteFile}>
                      <Trash2 className='size-4 text-destructive' />
                    </Button>
                  </span>
                </div>
              ))
            ) : (
              <div className='px-3 py-8 text-center text-sm text-muted-foreground'>{messages.emptyFiles}</div>
            )}
          </div>
        </div>
      </DialogShell>
    </>
  )
}

async function downloadSSHFile(sessionID: string, entry: DesktopDriveEntry) {
  const response = await fetch(`/api/connections/${sessionID}/sftp/download?path=${encodeURIComponent(entry.path)}`, {
    credentials: 'same-origin',
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string }
    throw new ApiError(payload.error || response.statusText, response.status, false, payload)
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = entry.name || 'download'
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

async function uploadSSHFile(sessionID: string, path: string, file: File) {
  const form = new FormData()
  form.set('path', path)
  form.set('file', file, file.name)
  const response = await fetch(`/api/connections/${sessionID}/sftp/upload`, {
    method: 'POST',
    credentials: 'same-origin',
    body: form,
  })
  const payload = (await response.json().catch(() => ({}))) as { error?: string }
  if (!response.ok) {
    throw new ApiError(payload.error || response.statusText, response.status, false, payload)
  }
  return payload
}

function parentRemotePath(value: string) {
  const normalized = value.trim().replaceAll('\\', '/').replace(/\/+$/g, '')
  if (!normalized || normalized === '.') return ''
  const separator = normalized.lastIndexOf('/')
  if (separator < 0) return ''
  if (separator === 0) return '/'
  return normalized.slice(0, separator)
}

function resolveWorkspaceWatermark(template: string, user: string, asset: string) {
  return template
    .trim()
    .replaceAll('{{user}}', user)
    .replaceAll('{{asset}}', asset)
    .replaceAll('${user}', user)
    .replaceAll('${asset}', asset)
}

async function downloadDesktopDriveFile(sessionID: string, entry: DesktopDriveEntry) {
  const response = await fetch(`/api/connections/${sessionID}/drive/download?path=${encodeURIComponent(entry.path)}`, {
    credentials: 'same-origin',
  })
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as { error?: string }
    throw new ApiError(payload.error || response.statusText, response.status, false, payload)
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = entry.name || 'download'
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

async function uploadDesktopDriveFile(sessionID: string, path: string, file: File) {
  const form = new FormData()
  form.set('path', path)
  form.set('file', file, file.name)
  const response = await fetch(`/api/connections/${sessionID}/drive/upload`, {
    method: 'POST',
    credentials: 'same-origin',
    body: form,
  })
  const payload = (await response.json().catch(() => ({}))) as { error?: string }
  if (!response.ok) {
    throw new ApiError(payload.error || response.statusText, response.status, false, payload)
  }
  return payload
}

function formatBytes(value: number) {
  if (!Number.isFinite(value) || value <= 0) return '0 B'
  if (value < 1024) return `${value} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let current = value / 1024
  for (const unit of units) {
    if (current < 1024) return `${current.toFixed(current >= 10 ? 0 : 1)} ${unit}`
    current /= 1024
  }
  return `${current.toFixed(0)} PB`
}

async function copyTextToClipboard(text: string) {
  if (navigator.clipboard?.writeText && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.setAttribute('readonly', 'true')
  textarea.style.position = 'fixed'
  textarea.style.top = '-1000px'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  textarea.select()
  const copied = document.execCommand('copy')
  textarea.remove()
  if (!copied) throw new Error('copy failed')
}
