import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const source = readFileSync(join(root, 'src/features/console/platform-page.tsx'), 'utf8')

const requirements = [
  ['agent gateway status endpoint is queried', source.includes("'/api/admin/agent-gateways/status'")],
  ['gateway group status endpoint is queried', source.includes("'/api/admin/gateway-groups/status'")],
  ['gateway status dialog is reachable from row actions', source.includes("type: 'gateway-status'") && source.includes('<GatewayStatusDialog')],
  ['agent resource metrics are rendered', ['memory_used_bytes', 'disk_used_bytes', 'network_rx_bytes', 'network_tx_bytes', 'active_sessions', 'last_heartbeat_at'].every((field) => source.includes(field))],
  ['gateway routing members are rendered', ['selected_gateway_id', 'required_capabilities', 'GatewayGroupStatusContent'].every((field) => source.includes(field))],
]

const failed = requirements.filter(([, passed]) => !passed)
if (failed.length > 0) {
  for (const [name] of failed) console.error(`Gateway observability check failed: ${name}`)
  process.exit(1)
}
