import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const read = (relativePath) => readFileSync(join(root, relativePath), 'utf8')

const sources = {
  router: read('src/routes/router.tsx'),
  settings: read('src/features/console/settings-page.tsx'),
  platform: read('src/features/console/platform-page.tsx'),
  unified: read('src/features/console/unified-settings-page.tsx'),
}

const requirements = [
  ['settings route uses the unified page', sources.router.includes("path: '/app/settings'") && sources.router.includes('<UnifiedSettingsPage />')],
  ['about route targets the about section', sources.router.includes("path: '/app/about'") && sources.router.includes("initialSection='about'")],
  ['system settings route maps to the system section', sources.router.includes("page.collection === 'system_settings'") && sources.router.includes("return 'system'")],
  ['login policy routes map to login security', sources.router.includes("page.collection === 'login_policies'") && sources.router.includes("page.collection === 'login_locks'") && sources.router.includes("return 'login-security'")],
  ['profile section anchor exists', sources.settings.includes("id='settings-profile'")],
  ['login security section anchor exists', sources.settings.includes("id='settings-login-security'")],
  ['about section anchor exists', sources.settings.includes("id='settings-about'")],
  ['system section anchor is forwarded', sources.unified.includes("sectionId='settings-system'") && sources.platform.includes('id={sectionId}')],
  ['system settings are permission gated', sources.unified.includes("canUseAPI(app.auth?.role") && sources.unified.includes('systemSettingsConfig && canReadSystemSettings')],
]

const failed = requirements.filter(([, passed]) => !passed)
if (failed.length > 0) {
  for (const [name] of failed) console.error(`Unified settings routing check failed: ${name}`)
  process.exit(1)
}
