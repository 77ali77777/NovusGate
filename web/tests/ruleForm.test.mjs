import assert from 'node:assert/strict'
import { test } from 'node:test'
import { autoRuleName, missingStep, presetOf, ruleSummary, withPreset } from '../src/lib/vpnRule.ts'

// VLAN plan M2: the rule form asks Who → To whom → What → Direction →
// Decision and says the result in one plain sentence.

const base = { name: '', source_type: 'any', dest_type: 'any', protocol: 'all', port: '', action: 'accept' }

test('missingStep names the first side that still needs a choice', () => {
  assert.equal(missingStep(base), null)
  assert.equal(missingStep({ ...base, source_type: 'network' }), 'source')
  assert.equal(missingStep({ ...base, source_type: 'network', source_network_id: 'n1', dest_type: 'node' }), 'dest')
  assert.equal(missingStep({ ...base, source_type: 'group', source_group_id: 'g', dest_type: 'custom', dest_ip: ' ' }), 'dest')
  assert.equal(missingStep({ ...base, source_type: 'custom', source_ip: '10.0.0.0/24' }), null)
  // A device is picked after its network; the network alone is not enough.
  assert.equal(missingStep({ ...base, source_type: 'node', source_network_id: 'n1' }), 'source')
})

test('autoRuleName shows the direction', () => {
  assert.equal(autoRuleName('Office A', 'Office B', false), 'Office A → Office B')
  assert.equal(autoRuleName('Office A', 'Office B', true), 'Office A ⇄ Office B')
  assert.equal(autoRuleName('a'.repeat(200), 'b'.repeat(200), false).length, 255)
})

test('service presets set protocol and port, and are recognised back', () => {
  assert.deepEqual(withPreset(base, 'rdp'), { ...base, protocol: 'tcp', port: '3389' })
  assert.deepEqual(withPreset({ ...base, protocol: 'tcp', port: '22' }, 'ping'), { ...base, protocol: 'icmp', port: '' })
  assert.equal(presetOf({ protocol: 'tcp', port: '80,443' }), 'web')
  assert.equal(presetOf({ protocol: 'tcp', port: '8080' }), undefined)
  assert.equal(presetOf({ protocol: 'all', port: '' }), undefined)
})

test('ruleSummary picks the sentence for decision and direction', () => {
  assert.deepEqual(ruleSummary({ ...base, bidirectional: true }), {
    key: 'allow.mutual',
    what: { key: 'all', params: {} },
  })
  assert.equal(ruleSummary({ ...base, action: 'drop' }).key, 'block.oneWay')
  assert.equal(ruleSummary({ ...base, action: 'reject', bidirectional: true }).key, 'block.mutual')
  assert.deepEqual(ruleSummary({ ...base, protocol: 'tcp', port: '22' }).what, {
    key: 'port',
    params: { proto: 'TCP', port: '22' },
  })
  assert.deepEqual(ruleSummary({ ...base, protocol: 'udp', port: '' }).what, { key: 'proto', params: { proto: 'UDP' } })
  assert.deepEqual(ruleSummary({ ...base, protocol: 'icmp' }).what, { key: 'ping', params: {} })
})
