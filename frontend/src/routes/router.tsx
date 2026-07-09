import {
  Navigate,
  Outlet,
  createRootRoute,
  createRoute,
  createRouter,
} from '@tanstack/react-router'
import { Loader2 } from 'lucide-react'
import { Toaster } from 'sonner'
import type { ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { useApp } from '@/app/app-provider'
import { SystemBrand } from '@/components/layout/system-brand'
import { AuthenticatedLayout } from '@/components/layout/authenticated-layout'
import { NavigationProgress } from '@/components/navigation-progress'
import { PublicAboutPage } from '@/features/about/about-page'
import { AuthPage } from '@/features/auth/auth-page'
import { AuditPage } from '@/features/console/audit-page'
import { OverviewPage } from '@/features/console/overview-page'
import { ServersPage } from '@/features/console/servers-page'
import { SettingsPage } from '@/features/console/settings-page'
import { SessionsPage } from '@/features/console/sessions-page'
import { AccessPortalPage, PlatformPage } from '@/features/console/platform-page'
import { HomePage } from '@/features/home/home-page'
import { ModalHost } from '@/features/modals/modal-host'
import { WorkspaceView } from '@/features/workspace/workspace-view'
import { platformPages, type PlatformPageConfig } from '@/lib/platform'
import { canViewPlatformPage, isAdminRole } from '@/lib/rbac'

function RootLayout() {
  const app = useApp()
  return (
    <>
      <NavigationProgress />
      {app.workspace ? <WorkspaceView /> : <Outlet />}
      <ModalHost />
      <Toaster richColors position='bottom-right' />
    </>
  )
}

function LoadingScreen() {
  const { t } = useTranslation()

  return (
    <div className='grid min-h-svh place-items-center bg-background text-foreground'>
      <div className='grid gap-4 text-center'>
        <SystemBrand className='justify-center' />
        <div className='inline-flex items-center gap-2 rounded-lg border border-border bg-card px-4 py-3 text-sm text-muted-foreground'>
          <Loader2 className='size-4 animate-spin' />
          {t('loadingConsole')}
        </div>
      </div>
    </div>
  )
}

function ConsoleGate({ children }: { children: ReactNode }) {
  const app = useApp()
  if (!app.booted) return <LoadingScreen />
  if (!app.auth) return <Navigate to='/login' replace />
  return <AuthenticatedLayout>{children}</AuthenticatedLayout>
}

function RoleGate({ children, adminOnly, page }: { children: ReactNode; adminOnly?: boolean; page?: PlatformPageConfig }) {
  const app = useApp()
  const role = app.auth?.role
  if (adminOnly && !isAdminRole(role)) return <Navigate to='/access' replace />
  if (page && !canViewPlatformPage(role, page, app.auth?.menu_permissions)) return <Navigate to='/access' replace />
  return children
}

function LoginGate() {
  const app = useApp()
  if (!app.booted) return <LoadingScreen />
  if (app.auth) {
    const next = new URLSearchParams(window.location.search).get('next')
    if (next && next.startsWith('/') && !next.startsWith('//')) {
      window.location.assign(next)
      return <LoadingScreen />
    }
    return <Navigate to='/app' replace />
  }
  return <AuthPage />
}

const rootRoute = createRootRoute({ component: RootLayout })

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  component: HomePage,
})

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: LoginGate,
})

const aboutRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/about',
  component: PublicAboutPage,
})

const legacySignInRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/sign-in',
  component: LoginGate,
})

const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/app',
  component: () => <ConsoleGate><OverviewPage /></ConsoleGate>,
})

const serversRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/app/servers',
  component: () => <ConsoleGate><RoleGate adminOnly><ServersPage /></RoleGate></ConsoleGate>,
})

const accessRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/access',
  component: () => <ConsoleGate><AccessPortalPage /></ConsoleGate>,
})

const appAccessRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/app/access',
  component: () => <ConsoleGate><AccessPortalPage /></ConsoleGate>,
})

const sessionsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/app/sessions',
  component: () => <ConsoleGate><SessionsPage /></ConsoleGate>,
})

const auditRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/app/audit',
  component: () => <ConsoleGate><AuditPage /></ConsoleGate>,
})

const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/app/settings',
  component: () => <ConsoleGate><SettingsPage /></ConsoleGate>,
})

const appAboutRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/app/about',
  component: () => <Navigate to='/app/settings' replace />,
})

const legacyDashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/dashboard',
  component: () => <Navigate to='/app' replace />,
})

const platformRoutes = platformPages.map((page) => createRoute({
  getParentRoute: () => rootRoute,
  path: page.route,
  component: () => <ConsoleGate><RoleGate page={page}><PlatformPage config={page} /></RoleGate></ConsoleGate>,
}))

const routeTree = rootRoute.addChildren([
  indexRoute,
  aboutRoute,
  loginRoute,
  legacySignInRoute,
  appRoute,
  accessRoute,
  appAccessRoute,
  serversRoute,
  sessionsRoute,
  auditRoute,
  settingsRoute,
  appAboutRoute,
  legacyDashboardRoute,
  ...platformRoutes,
])

export const router = createRouter({ routeTree })

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
