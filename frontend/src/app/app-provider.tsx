import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { toast } from 'sonner'

import { ApiError, apiRequest } from '@/lib/api'
import { translate } from '@/lib/i18n'
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
    { title: '产品', href: '#product' },
    { title: '连接', href: '#connections' },
    { title: '安全', href: '#security' },
    { title: '部署', href: '#deploy' },
  ],
}

const defaultAppearance: ThemeAppearance = {
  preset: 'default',
  font: 'default',
  radius: 'default',
  scale: 'default',
  contentLayout: 'full',
  sidebarStyle: 'default',
}

const AppContext = createContext<AppContextValue | null>(null)

function readStoredTheme(): Theme {
  const stored = localStorage.getItem('servermanager:theme')
  return stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system'
}

function readSystemTheme(): ResolvedTheme {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function readStoredLocale(): Locale {
  const stored = localStorage.getItem('servermanager:locale')
  return stored === 'en-US' || stored === 'zh-CN' ? stored : 'zh-CN'
}

function readStoredAppearance(): ThemeAppearance {
  const stored = localStorage.getItem('servermanager:appearance')
  if (!stored) return defaultAppearance
  try {
    const parsed = JSON.parse(stored) as Partial<ThemeAppearance>
    return {
      preset: parsed.preset || defaultAppearance.preset,
      font: parsed.font || defaultAppearance.font,
      radius: parsed.radius || defaultAppearance.radius,
      scale: parsed.scale || defaultAppearance.scale,
      contentLayout: parsed.contentLayout || defaultAppearance.contentLayout,
      sidebarStyle: parsed.sidebarStyle || defaultAppearance.sidebarStyle,
    }
  } catch {
    return defaultAppearance
  }
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

export function AppProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [theme, setThemeState] = useState<Theme>(readStoredTheme)
  const [systemTheme, setSystemTheme] = useState<ResolvedTheme>(readSystemTheme)
  const [locale, setLocaleState] = useState<Locale>(readStoredLocale)
  const [appearance, setAppearanceState] = useState<ThemeAppearance>(readStoredAppearance)
  const [modal, setModal] = useState<ModalState>(null)
  const [workspace, setWorkspace] = useState<WorkspaceState>(null)
  const resolvedTheme = theme === 'system' ? systemTheme : theme

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

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next)
  }, [])

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
  }, [])

  const setAppearance = useCallback((next: Partial<ThemeAppearance>) => {
    setAppearanceState((current) => ({ ...current, ...next }))
  }, [])

  const resetAppearance = useCallback(() => {
    setAppearanceState(defaultAppearance)
  }, [])

  const t = useCallback((key: string, fallback?: string) => translate(locale, key, fallback), [locale])

  useEffect(() => {
    const query = window.matchMedia('(prefers-color-scheme: dark)')
    const updateSystemTheme = () => setSystemTheme(query.matches ? 'dark' : 'light')
    updateSystemTheme()
    query.addEventListener('change', updateSystemTheme)
    return () => query.removeEventListener('change', updateSystemTheme)
  }, [])

  useEffect(() => {
    localStorage.setItem('servermanager:theme', theme)
  }, [theme])

  useEffect(() => {
    localStorage.setItem('servermanager:locale', locale)
    document.documentElement.lang = locale === 'zh-CN' ? 'zh-CN' : 'en'
  }, [locale])

  useEffect(() => {
    localStorage.setItem('servermanager:appearance', JSON.stringify(appearance))
    applyBodyAttribute('data-theme-preset', appearance.preset, defaultAppearance.preset)
    applyBodyAttribute('data-theme-font', appearance.font === 'default' ? 'sans' : appearance.font, 'sans')
    applyBodyAttribute('data-theme-radius', appearance.radius, defaultAppearance.radius)
    applyBodyAttribute('data-theme-scale', appearance.scale, defaultAppearance.scale)
    applyBodyAttribute('data-theme-content-layout', appearance.contentLayout, defaultAppearance.contentLayout)
    applyBodyAttribute('data-theme-sidebar-style', appearance.sidebarStyle, defaultAppearance.sidebarStyle)
  }, [appearance])

  useEffect(() => {
    const root = document.documentElement
    root.classList.toggle('dark', resolvedTheme === 'dark')
    root.style.colorScheme = resolvedTheme

    const themeColor = resolvedTheme === 'dark' ? '#1f1f1f' : '#ffffff'
    let metaThemeColor = document.querySelector<HTMLMetaElement>("meta[name='theme-color']")
    if (!metaThemeColor) {
      metaThemeColor = document.createElement('meta')
      metaThemeColor.name = 'theme-color'
      document.head.appendChild(metaThemeColor)
    }
    metaThemeColor.content = themeColor
  }, [resolvedTheme])

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
      booted,
      configured,
      data,
      handleApiError,
      logout,
      modal,
      publicConfig,
      appearance,
      refresh,
      resolvedTheme,
      locale,
      resetAppearance,
      setAuthenticatedUser,
      setAppearance,
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
