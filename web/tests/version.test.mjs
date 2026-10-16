import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { test } from 'node:test'

// One release number everywhere: the panel (web/package.json, shown in the
// sidebar), the control plane (server/internal/shared/version) and
// NovusGate Center (its package.json, shown in its header and /api/health).
// The other two are checked when this runs in the full repository; the web
// build container only has web/.

const RELEASE = '0.7.0'
const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8')
const has = (rel) => existsSync(new URL(rel, import.meta.url))

test('the panel shows the release from its package.json', () => {
  assert.equal(JSON.parse(read('../package.json')).version, RELEASE)
  const layout = read('../src/components/Layout.tsx')
  assert.ok(layout.includes('__APP_VERSION__'), 'the sidebar reads the version, not a literal')
  assert.ok(!/NovusGate v\d/.test(layout), 'no hard-coded version in the sidebar')
})

test('the control plane and Center carry the same release', { skip: !has('../../server/go.mod') }, () => {
  const go = read('../../server/internal/shared/version/version.go')
  assert.match(go, new RegExp(`Version = "${RELEASE.replaceAll('.', '\\.')}"`))
  assert.equal(JSON.parse(read('../../NovusGate Center/package.json')).version, RELEASE)
})
