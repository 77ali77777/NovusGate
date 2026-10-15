import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

const spec = '../server/internal/controlplane/api/rest/testdata/openapi.json'

// src/api/openapi.d.ts must match the backend's OpenAPI document; after an
// API change run `npm run gen:api`. Skipped when the server tree is absent.
test('generated API types are up to date', { skip: !existsSync(spec) && 'server tree not present' }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'ng-openapi-'))
  try {
    const out = join(dir, 'openapi.d.ts')
    execFileSync(process.execPath, ['node_modules/openapi-typescript/bin/cli.js', spec, '-o', out], { stdio: 'pipe' })
    assert.equal(readFileSync('src/api/openapi.d.ts', 'utf8'), readFileSync(out, 'utf8'), 'run npm run gen:api')
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
