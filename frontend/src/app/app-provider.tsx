import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'

import { ApiError, apiRequest } from '@/lib/api'
import type { AuthUser, BootstrapData, ModalState, Theme, WorkspaceState } from '@/types'

interface AppContextValue {
  auth: AuthUser | null
  booted: boolean
  configured: boolean
  setupRequired: boolean
  data: BootstrapData
  modal: ModalState
  workspace: WorkspaceState
  theme: Theme
  setTheme: (theme: Theme) => void
  setModal: (modal: ModalState) => void
  setWorkspace: (workspace: WorkspaceState) => void
  setAuthenticatedUser: (user: AuthUser) => void
  refresh: (silent?: boolean) => Promise<void>
  logout: () => Promise<void>
  showToast: (message: string) => void
  handleApiError: (error: unknown) => void
}

const emptyBootstrap: BootstrapData = {
  servers: [],
  credentials: [],
  sessions: [],
  audit_logs: [],
}

const AppContext = createContext<AppContextValue | null>(null)

export function AppProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [theme, setThemeState] = useState<Theme>(() => (localStorage.getItem('servermanager:theme') as Theme) || 'light')
  const [modal, setModal] = useState<ModalState>(null)
  const [workspace, setWorkspace] = useState<WorkspaceState>(null)

  const authStatus = useQuery({
    queryKey: ['auth-status'],
    queryFn: () => apiRequest<{ configured: boolean }>('/api/auth/status'),
    retry: false,
  })

  const configured = Boolean(authStatus.data?.configured)

  const meQuery = useQuery({
    queryKey: ['auth-me'],
    queryFn: () => apiRequest<{ user: AuthUser }>('/api/auth/me'),
    enabled: configured,
    retry: false,
  })

  const auth = meQuery.data?.user ?? null

  const bootstrapQuery = useQuery({
    queryKey: ['bootstrap'],
    queryFn: () => apiRequest<BootstrapData>('/api/bootstrap'),
    enabled: Boolean(auth),
    retry: false,
  })

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next)
  }, [])

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    localStorage.setItem('servermanager:theme', theme)
  }, [theme])

  const showToast = useCallback((message: string) => toast(message), [])

  const handleApiError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.setupRequired) {
        queryClient.setQueryData(['auth-status'], { configured: false })
        queryClient.removeQueries({ queryKey: ['auth-me'] })
        queryClient.removeQueries({ queryKey: ['bootstrap'] })
        setWorkspace(null)
      }
      toast.error(error instanceof Error ? error.message : '操作失败')
    },
    [queryClient]
  )

  const setAuthenticatedUser = useCallback(
    (user: AuthUser) => {
      queryClient.setQueryData(['auth-status'], { configured: true })
      queryClient.setQueryData(['auth-me'], { user })
    },
    [queryClient]
  )

  const refresh = useCallback(
    async (silent = false) => {
      await queryClient.invalidateQueries({ queryKey: ['bootstrap'] })
      if (!silent) toast.success('数据已刷新')
    },
    [queryClient]
  )

  const logoutMutation = useMutation({
    mutationFn: () => apiRequest('/api/auth/logout', { method: 'POST', body: '{}' }),
    onSettled: () => {
      queryClient.removeQueries({ queryKey: ['auth-me'] })
      queryClient.removeQueries({ queryKey: ['bootstrap'] })
      setWorkspace(null)
      setModal(null)
    },
  })

  const logout = useCallback(async () => {
    await logoutMutation.mutateAsync().catch(() => undefined)
  }, [logoutMutation])

  const data = bootstrapQuery.data
    ? {
        servers: bootstrapQuery.data.servers || [],
        credentials: bootstrapQuery.data.credentials || [],
        sessions: bootstrapQuery.data.sessions || [],
        audit_logs: bootstrapQuery.data.audit_logs || [],
        guacd: bootstrapQuery.data.guacd,
      }
    : emptyBootstrap

  const booted = authStatus.isFetched && (!configured || meQuery.isFetched || meQuery.isError)

  const value = useMemo<AppContextValue>(
    () => ({
      auth,
      booted,
      configured,
      setupRequired: authStatus.isFetched ? !configured : false,
      data,
      modal,
      workspace,
      theme,
      setTheme,
      setModal,
      setWorkspace,
      setAuthenticatedUser,
      refresh,
      logout,
      showToast,
      handleApiError,
    }),
    [
      auth,
      authStatus.isFetched,
      booted,
      configured,
      data,
      handleApiError,
      logout,
      modal,
      refresh,
      setAuthenticatedUser,
      setTheme,
      showToast,
      theme,
      workspace,
    ]
  )

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>
}

export function useApp() {
  const context = useContext(AppContext)
  if (!context) throw new Error('useApp must be used inside AppProvider')
  return context
}
