import assert from 'node:assert/strict'
import { test } from 'node:test'
import { jsxTags, scanHelp, sourceFiles } from './helpScan.mjs'

// User requirement (2026-10-15): every input in every section has a "?"
// that says what it is, who needs it and why, and what changing it does.
test('every input has a help tip with what, who and effect in en and az', () => {
  const problems = scanHelp(sourceFiles())
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

// Found in the browser: at 375 px the tip started at x=188 and was 288 px
// wide, so it ran off the right edge.
test('tipShift keeps the tip inside the screen', async () => {
  const { tipShift } = await import('../src/lib/helpTip.ts')
  assert.equal(tipShift(100, 288, 1200), 0, 'fits: no shift')
  assert.equal(tipShift(188, 288, 375), 375 - 8 - (188 + 288), 'moved left to the margin')
  assert.equal(tipShift(-20, 288, 1200), 28, 'moved right to the margin')
  assert.equal(tipShift(4, 400, 375), 4, 'wider than the screen: left edge at the margin')
})
