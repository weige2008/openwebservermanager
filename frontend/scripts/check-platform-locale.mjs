import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const root = dirname(dirname(fileURLToPath(import.meta.url)))
const platformSource = readFileSync(join(root, 'src/lib/platform.ts'), 'utf8')

const mojibakeFragments = [
  '�',
  '€',
  '銆',
  '璧勪',
  '缁熶',
  '鐢ㄦ',
  '鏃ュ',
  '绯荤',
  '鎺ュ',
  '鍛戒',
  '鏁版',
  '閮ㄩ',
  '瑙掕',
  '鐧诲',
  '瀹氭',
  '鎿嶄',
  '绂荤',
  '韬',
  '乁',
  '丄',
  '丏',
  '乵',
]

const found = mojibakeFragments.filter((fragment) => platformSource.includes(fragment))

if (found.length > 0) {
  console.error(`platform locale text contains mojibake fragments: ${found.join(', ')}`)
  process.exit(1)
}
