import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const source = readFileSync(join(root, 'src/features/console/platform-page.tsx'), 'utf8')

const requirements = [
  ['managed workflow collection set exists', source.includes("new Set(['command_approvals', 'sql_work_orders'])")],
  ['managed workflows participate in read-only state', source.includes('const collectionReadOnly = auditReadOnly || workflowReadOnly')],
  ['generic create is disabled for managed workflows', source.includes("const canCreate = !collectionReadOnly && canUsePath('POST', apiPath)")],
  ['generic edit is disabled for managed workflows', source.includes('const canEditItem = (item: PlatformItem) => !collectionReadOnly')],
  ['generic delete is disabled for managed workflows', source.includes('const canDeleteItem = (item: PlatformItem) => !collectionReadOnly')],
  ['bulk delete is disabled for managed workflows', source.includes('Boolean(config.apiPath && !collectionReadOnly)')],
  ['SQL decisions use dedicated endpoints', source.includes("config.collection === 'sql_work_orders'") && source.includes("decision: 'approve'") && source.includes("decision: 'reject'")],
  ['command decisions use dedicated endpoints', source.includes("config.collection === 'command_approvals'") && source.includes("type: 'command-decision'")],
]

const failed = requirements.filter(([, passed]) => !passed)
if (failed.length > 0) {
  for (const [name] of failed) console.error(`Managed workflow check failed: ${name}`)
  process.exit(1)
}
