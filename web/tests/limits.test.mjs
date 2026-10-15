import assert from 'node:assert/strict'
import { test } from 'node:test'
import { formatRate, kbpsToMbps, mbpsToKbps, scheduleSummary } from '../src/lib/limits.ts'

test('mbpsToKbps: empty is unlimited, numbers become kbit/s, junk is invalid', () => {
  assert.equal(mbpsToKbps(''), null)
  assert.equal(mbpsToKbps('  '), null)
  assert.equal(mbpsToKbps('2'), 2000)
  assert.equal(mbpsToKbps('0.5'), 500)
  assert.equal(mbpsToKbps('1,5'), 1500) // decimal comma
  assert.equal(mbpsToKbps('0.0001'), 1) // never rounds to zero
  assert.equal(mbpsToKbps('0'), 'invalid')
  assert.equal(mbpsToKbps('-1'), 'invalid')
  assert.equal(mbpsToKbps('abc'), 'invalid')
  assert.equal(mbpsToKbps('100001'), 'invalid') // above 100 Gbit/s
})

test('kbpsToMbps fills the form back', () => {
  assert.equal(kbpsToMbps(null), '')
  assert.equal(kbpsToMbps(undefined), '')
  assert.equal(kbpsToMbps(2000), '2')
  assert.equal(kbpsToMbps(1500), '1.5')
  assert.equal(kbpsToMbps(1), '0.001')
})

test('formatRate picks Mbit/s or kbit/s', () => {
  assert.equal(formatRate(2000), '2 Mbit/s')
  assert.equal(formatRate(1500), '1.5 Mbit/s')
  assert.equal(formatRate(512), '512 kbit/s')
})

test('scheduleSummary names the days in week order with the hours', () => {
  const names = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
  assert.equal(
    scheduleSummary([{ days: [5, 1, 2], from: '08:00', to: '18:00' }], names),
    'Mon, Tue, Fri 08:00–18:00'
  )
  assert.equal(
    scheduleSummary(
      [
        { days: [6], from: '22:00', to: '02:00' },
        { days: [0], from: '10:00', to: '24:00' },
      ],
      names
    ),
    'Sat 22:00–02:00; Sun 10:00–24:00'
  )
  assert.equal(scheduleSummary([], names), '')
  assert.equal(scheduleSummary(null, names), '')
})
