import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { systemRules } from '../src/lib/systemRules.ts'

// Explanations are translation keys; the English text is what the view shows.
const en = JSON.parse(readFileSync(new URL('../src/i18n/locales/en/firewallv2.json', import.meta.url), 'utf8'))
const english = (key) => key.split('.').reduce((o, k) => o?.[k], en)

// A trimmed compiled ruleset (same shape as server/internal/netctl/nft/testdata/full.nft).
const script = `table inet novusgate
delete table inet novusgate
table inet novusgate {
	set ssh_ports {
		type inet_service
		elements = { 22 }
	}
	chain input {
		type filter hook input priority filter - 10; policy drop;
		iif "lo" accept
		ip saddr @blocked_v4 counter drop
		ct state established,related accept
		tcp dport @ssh_ports accept
		tcp dport 443 accept comment "svc:abc"
		ip saddr 203.0.113.0/24 accept comment "ip:def"
		counter comment "default drop"
	}
	chain vpn_policy {
		ip saddr 10.20.0.0/24 counter drop comment "rule:x"
		iifname "wg1" oifname "wg1" accept
		counter drop comment "vpn default drop"
	}
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "eth0" tcp dport 8081 dnat ip to 10.20.0.5:80 comment "fwd:cam"
	}
}
`

test('systemRules keeps the rules NovusGate adds and explains them', () => {
  const got = systemRules(script)
  assert.deepEqual(
    got.map((r) => `${r.chain}|${r.rule}`),
    [
      'input|iif "lo" accept',
      'input|ip saddr @blocked_v4 counter drop',
      'input|ct state established,related accept',
      'input|tcp dport @ssh_ports accept',
      'input|counter comment "default drop"',
      'vpn_policy|iifname "wg1" oifname "wg1" accept',
      'vpn_policy|counter drop comment "vpn default drop"',
    ]
  )
  assert.equal(got[0].explanation, 'systemRules.explain.loopback')
  assert.equal(got[3].explanation, 'systemRules.explain.ssh')
  assert.equal(got[4].explanation, 'systemRules.explain.defaultDrop')
  assert.equal(got[5].explanation, 'systemRules.explain.sameNetwork')
  assert.match(english(got[0].explanation), /loopback/i)
  assert.match(english(got[3].explanation), /SSH/)
  assert.match(english(got[4].explanation), /dropped/)
  assert.match(english(got[5].explanation), /same network/)
  // every explanation key has an English text
  for (const r of got) assert.equal(typeof english(r.explanation), 'string', r.explanation)
})

test('systemRules reports each chain policy', () => {
  const got = systemRules(script)
  assert.equal(got[0].policy, 'drop')
  assert.equal(got[5].policy, '') // vpn_policy is a regular chain
})

test('an unknown system rule is kept without an explanation', () => {
  const got = systemRules('table inet novusgate {\n\tchain input {\n\t\tmeta mark 7 accept\n\t}\n}\n')
  assert.equal(got.length, 1)
  assert.equal(got[0].explanation, '')
})

// Limit profiles (P9b): the per-profile rules carry "limit:" comments and are
// panel-made; the jumps and schedule windows are explained.
test('systemRules leaves out limit rules and explains the limit plumbing', () => {
  const got = systemRules(`table inet novusgate {
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		jump limits
		ct state established,related accept
	}
	chain limits {
		ip saddr @lim_0 jump lim_0_time
		ip saddr @lim_0 update @lim_0_up { ip saddr limit rate over 125000 bytes/second burst 31250 bytes } counter drop comment "limit:p:up"
	}
	chain lim_0_time {
		meta day "Monday" meta hour "04:00:00"-"13:59:59" return
		counter drop comment "limit:p:schedule"
	}
}
`)
  assert.deepEqual(
    got.map((r) => [r.chain, r.explanation]),
    [
      ['forward', 'systemRules.explain.limits'],
      ['forward', 'systemRules.explain.established'],
      ['limits', 'systemRules.explain.limitSchedule'],
      ['lim_0_time', 'systemRules.explain.limitWindow'],
    ]
  )
  for (const r of got) assert.equal(typeof english(r.explanation), 'string', r.explanation)
})
