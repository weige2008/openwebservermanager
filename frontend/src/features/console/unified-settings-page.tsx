import { useEffect } from 'react'

import { useApp } from '@/app/app-provider'
import { PlatformSettingsPage } from '@/features/console/platform-page'
import { SettingsPage } from '@/features/console/settings-page'
import { platformPages } from '@/lib/platform'
import { canUseAPI } from '@/lib/rbac'

export type SettingsSection = 'profile' | 'login-security' | 'system' | 'about'

const systemSettingsConfig = platformPages.find((page) => page.collection === 'system_settings')

export function UnifiedSettingsPage({ initialSection = 'profile' }: { initialSection?: SettingsSection }) {
  const app = useApp()
  const canReadSystemSettings = canUseAPI(app.auth?.role, app.auth?.api_permissions || [], 'GET', '/api/admin/system-settings')

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      document.getElementById(`settings-${initialSection}`)?.scrollIntoView({ block: 'start' })
    })
    return () => cancelAnimationFrame(frame)
  }, [initialSection])

  return (
    <div className='grid gap-4'>
      <SettingsPage />
      {systemSettingsConfig && canReadSystemSettings ? <PlatformSettingsPage config={systemSettingsConfig} sectionId='settings-system' /> : null}
    </div>
  )
}
