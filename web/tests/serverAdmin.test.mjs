import assert from 'node:assert/strict'
import { test } from 'node:test'
import { errorBodyCode } from '../src/api/errors.ts'
import {
  addressRows,
  routeRows,
  StepUpCancelled,
  sysctlField,
  withStepUp,
} from '../src/lib/serverAdmin.ts'

const stepUpError = { response: { status: 403, data: { error: { code: 'step_up_required', message: 'x' } } } }

test('errorBodyCode reads the unified error code', () => {
  assert.equal(errorBodyCode(stepUpError), 'step_up_required')
  assert.equal(errorBodyCode({ response: { data: { error: 'old style' } } }), undefined)
  assert.equal(errorBodyCode(new Error('network')), undefined)
})

test('withStepUp asks for the password once and retries', async () => {
  let calls = 0
  let asked = 0
  const result = await withStepUp(
    async () => {
      calls++
      if (calls === 1) throw stepUpError
      return 'done'
    },
    async () => {
      asked++
    }
  )
  assert.equal(result, 'done')
  assert.equal(calls, 2)
  assert.equal(asked, 1)
})

test('withStepUp passes other errors through without asking', async () => {
  let asked = 0
  const other = { response: { status: 400, data: { error: { code: 'invalid_hostname', message: 'x' } } } }
  await assert.rejects(
    withStepUp(
      async () => {
        throw other
      },
      async () => {
        asked++
      }
    ),
    (e) => e === other
  )
  assert.equal(asked, 0)
})

test('withStepUp stops when the password prompt is cancelled', async () => {
  let calls = 0
  await assert.rejects(
    withStepUp(
      async () => {
        calls++
        throw stepUpError
      },
      async () => {
        throw new StepUpCancelled()
      }
    ),
    StepUpCancelled
  )
  assert.equal(calls, 1)
})

test('addressRows flattens ip -j addr', () => {
  const rows = addressRows([
    {
      ifname: 'eth0',
      operstate: 'UP',
      addr_info: [
        { family: 'inet', local: '203.0.113.5', prefixlen: 24 },
        { family: 'inet6', local: 'fe80::1', prefixlen: 64 },
      ],
    },
    { ifname: 'wg0', operstate: 'UNKNOWN' },
    null,
    'junk',
  ])
  assert.deepEqual(rows, [
    { name: 'eth0', state: 'UP', addresses: ['203.0.113.5/24', 'fe80::1/64'] },
    { name: 'wg0', state: 'UNKNOWN', addresses: [] },
  ])
  assert.deepEqual(addressRows(null), [])
})

test('routeRows reads destination, gateway and device', () => {
  assert.deepEqual(
    routeRows([
      { dst: 'default', gateway: '203.0.113.1', dev: 'eth0' },
      { dst: '10.10.0.0/24', dev: 'wg0' },
    ]),
    [
      { dst: 'default', gateway: '203.0.113.1', dev: 'eth0' },
      { dst: '10.10.0.0/24', gateway: '', dev: 'wg0' },
    ]
  )
})

test('sysctlField mirrors the server allow-list', () => {
  assert.deepEqual(sysctlField('net.ipv4.ip_forward'), { kind: 'select', options: ['0', '1'] })
  assert.deepEqual(sysctlField('net.ipv4.tcp_congestion_control'), {
    kind: 'select',
    options: ['bbr', 'cubic'],
  })
  assert.deepEqual(sysctlField('net.netfilter.nf_conntrack_max'), {
    kind: 'number',
    min: 1024,
    max: 16777216,
  })
  assert.equal(sysctlField('kernel.panic'), undefined)
})
