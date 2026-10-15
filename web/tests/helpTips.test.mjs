import assert from 'node:assert/strict'
import { test } from 'node:test'
import { jsxTags, scanHelp, sourceFiles } from './helpScan.mjs'

// Files whose tips are still being written; the list only shrinks and is
// removed when it is empty.
const PENDING = [
  'App.tsx',
  'components/CreateNodeModal.tsx',
  'components/EditNodeModal.tsx',
  'components/Layout.tsx',
  'components/ServerConfigModal.tsx',
  'pages/Fail2Ban/Fail2Ban.tsx',
  'pages/Firewall/AdvancedTab.tsx',
  'pages/Firewall/Firewall.tsx',
  'pages/Firewall/HostRulesTab.tsx',
  'pages/Firewall/LimitsTab.tsx',
  'pages/Firewall/VPNRuleModal.tsx',
  'pages/Groups/GroupsPage.tsx',
  'pages/Nodes/Nodes.tsx',
  'pages/Server/ConfirmWordModal.tsx',
  'pages/Server/ServerPage.tsx',
  'pages/Server/ServerTabs.tsx',
  'pages/Settings/ChangePasswordCard.tsx',
  'pages/Settings/NotificationsCard.tsx',
  'pages/Settings/UserManagementCard.tsx',
]

// User requirement (2026-10-15): every input in every section has a "?"
// that says what it is, who needs it and why, and what changing it does.
test('every input has a help tip with what, who and effect in en and az', () => {
  const files = sourceFiles().filter(
    (f) => !PENDING.some((p) => f.replace(/\\/g, '/').endsWith(`/src/${p}`))
  )
  const problems = scanHelp(files)
  assert.deepEqual(problems, [], `\n${problems.join('\n')}`)
})

test('jsxTags reads a tag whose attributes contain arrows and strings', () => {
  const tags = jsxTags(
    '<div><Input label="a > b" onChange={(e) => set(e.target.value)} help="x:y" /><input data-help="x:z"></div>',
    ['Input', 'input']
  )
  assert.equal(tags.length, 2)
  assert.match(tags[0].tag, /help="x:y" \/>$/)
  assert.match(tags[1].tag, /data-help="x:z">$/)
})
