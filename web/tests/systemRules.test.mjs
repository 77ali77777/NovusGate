import assert from 'node:assert/strict'
import { test } from 'node:test'
import { systemRules } from '../src/lib/systemRules.ts'

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
  assert.match(got[0].explanation, /loopback/i)
  assert.match(got[3].explanation, /SSH/)
  assert.match(got[4].explanation, /dropped/)
  assert.match(got[5].explanation, /same network/)
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
