import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { normalizeInterfaceLanguage } from '@/i18n/languages'
import { ApiError, apiRequest } from '@/lib/api'
import { defaultAppearance, usePreferencesStore } from '@/stores/preferences-store'
import type { AuthUser, BootstrapData, Locale, ModalState, PublicConfig, ResolvedTheme, Theme, ThemeAppearance, WorkspaceState } from '@/types'

interface AppContextValue {
  auth: AuthUser | null
  booted: boolean
  configured: boolean
  setupRequired: boolean
  publicConfig: PublicConfig
  data: BootstrapData
  modal: ModalState
  workspace: WorkspaceState
  theme: Theme
  resolvedTheme: ResolvedTheme
  locale: Locale
  appearance: ThemeAppearance
  setTheme: (theme: Theme) => void
  setLocale: (locale: Locale) => void
  setAppearance: (appearance: Partial<ThemeAppearance>) => void
  resetAppearance: () => void
  t: (key: string, fallback?: string) => string
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

const defaultPublicConfig: PublicConfig = {
  site_name: 'ServerManager',
  nav_links: [
    { title: 'product', href: '#product' },
    { title: 'connections', href: '#connections' },
    { title: 'security', href: '#security' },
    { title: 'deploy', href: '#deploy' },
  ],
}

const AppContext = createContext<AppContextValue | null>(null)

function readSystemTheme(): ResolvedTheme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function applyBodyAttribute(name: string, value: string, fallback: string) {
  const body = document.body
  if (!body) return
  if (value === fallback) {
    body.removeAttribute(name)
    return
  }
  body.setAttribute(name, value)
}

function resolveThemeFont(appearance: ThemeAppearance) {
  if (appearance.font !== 'default') return appearance.font
  return appearance.preset === 'anthropic' ? 'serif' : 'sans'
}

export function AppProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const { i18n, t: translate } = useTranslation()
  const theme = usePreferencesStore((state) => state.theme)
  const appearance = usePreferencesStore((state) => state.appearance)
  const setTheme = usePreferencesStore((state) => state.setTheme)
  const setAppearance = usePreferencesStore((state) => state.setAppearance)
  const resetAppearance = usePreferencesStore((state) => state.resetAppearance)
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(readSystemTheme)
  const [modal, setModal] = useState<ModalState>(null)
  const [workspace, setWorkspace] = useState<WorkspaceState>(null)
  const resolvedTheme = theme === 'system' ? systemTheme : theme
  const locale = normalizeInterfaceLanguage(i18n.language)

  const authStatus = useQuery({
    queryKey: ['auth-status'],
    queryFn: () => apiRequest<{ configured: boolean }>('/api/auth/status'),
    retry: false,
  })

  const publicConfigQuery = useQuery({
    queryKey: ['public-config'],
    queryFn: () => apiRequest<PublicConfig>('/api/public/config'),
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

  const setLocale = useCallback(
    (next: Locale) => {
      void i18n.changeLanguage(next)
    },
    [i18n]
  )

  const t = useCallback((key: string, fallback?: string) => translate(key, { defaultValue: fallback ?? key }), [translate])

  useEffect(() => {
    const query = window.matchMedia('(prefers-color-scheme: dark)')
    const updateSystemTheme = () => setSystemTheme(query.matches ? 'dark' : 'light')
    updateSystemTheme()
    query.addEventListener('change', updateSystemTheme)
    return () => query.removeEventListener('change', updateSystemTheme)
  }, [])

  useEffect(() => {
    document.documentElement.lang = locale
  }, [locale])

  useEffect(() => {
    applyBodyAttribute('data-theme-preset', appearance.preset, defaultAppearance.preset)
    document.body.setAttribute('data-theme-font', resolveThemeFont(appearance))
    applyBodyAttribute('data-theme-radius', appearance.radius, defaultAppearance.radius)
    applyBodyAttribute('data-theme-scale', appearance.scale, defaultAppearance.scale)
    document.body.setAttribute('data-theme-content-layout', appearance.contentLayout)
    applyBodyAttribute('data-theme-sidebar-style', appearance.sidebarStyle, defaultAppearance.sidebarStyle)
  }, [appearance])

  useEffect(() => {
    const root = document.documentElement
    root.classList.toggle('dark', resolvedTheme === 'dark')
    root.style.colorScheme = resolvedTheme

    let metaThemeColor = document.querySelector<HTMLMetaElement>("meta[name='theme-color']")
    if (!metaThemeColor) {
      metaThemeColor = document.createElement('meta')
      metaThemeColor.name = 'theme-color'
      document.head.appendChild(metaThemeColor)
    }
    const themeColor = getComputedStyle(document.body).backgroundColor
    metaThemeColor.content = themeColor
  }, [resolvedTheme, appearance.preset])

  const showToast = useCallback((message: string) => toast(message), [])

  const handleApiError = useCallback(
    (error: unknown) => {
      if (error instanceof ApiError && error.setupRequired) {
        queryClient.setQueryData(['auth-status'], { configured: false })
        queryClient.removeQueries({ queryKey: ['auth-me'] })
        queryClient.removeQueries({ queryKey: ['bootstrap'] })
        setWorkspace(null)
      }
      toast.error(error instanceof Error ? error.message : t('operationFailed'))
    },
    [queryClient, t]
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
      if (!silent) toast.success(t('dataRefreshed'))
    },
    [queryClient, t]
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

  const publicConfig = publicConfigQuery.data
    ? {
        site_name: publicConfigQuery.data.site_name || defaultPublicConfig.site_name,
        nav_links: publicConfigQuery.data.nav_links?.length ? publicConfigQuery.data.nav_links : defaultPublicConfig.nav_links,
      }
    : defaultPublicConfig

  const booted = authStatus.isFetched && (!configured || meQuery.isFetched || meQuery.isError)

  const value = useMemo<AppContextValue>(
    () => ({
      auth,
      booted,
      configured,
      setupRequired: authStatus.isFetched ? !configured : false,
      publicConfig,
      data,
      modal,
      workspace,
      theme,
      resolvedTheme,
      locale,
      appearance,
      setTheme,
      setLocale,
      setAppearance,
      resetAppearance,
      t,
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
      appearance,
      booted,
      configured,
      data,
      handleApiError,
      locale,
      logout,
      modal,
      publicConfig,
      refresh,
      resetAppearance,
      resolvedTheme,
      setAppearance,
      setAuthenticatedUser,
      setLocale,
      setTheme,
      showToast,
      t,
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
