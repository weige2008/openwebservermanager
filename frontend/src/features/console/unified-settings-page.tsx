import { useEffect } from 'react'

import { PlatformSettingsPage } from '@/features/console/platform-page'
import { SettingsPage } from '@/features/console/settings-page'
import { platformPages } from '@/lib/platform'

export type SettingsSection = 'profile' | 'login-security' | 'system' | 'about'

const systemSettingsConfig = platformPages.find((page) => page.collection === 'system_settings')

export function UnifiedSettingsPage({ initialSection = 'profile' }: { initialSection?: SettingsSection }) {
  useEffect(() => {
    const frame = requestAnimationFrame(() => {
      document.getElementById(`settings-${initialSection}`)?.scrollIntoView({ block: 'start' })
    })
    return () => cancelAnimationFrame(frame)
  }, [initialSection])

  return (
    <div className='grid gap-4'>
      <SettingsPage />
      {systemSettingsConfig ? <PlatformSettingsPage config={systemSettingsConfig} sectionId='settings-system' /> : null}
    </div>
  )
}
