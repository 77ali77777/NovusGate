const test = require('node:test');
const assert = require('node:assert');
const { sameOrigin } = require('../lib/origin');

const req = (origin, host) => ({ headers: { ...(origin ? { origin } : {}), host } });

// The Center's own page talks to it from the same origin; a page from any
// other site must not reach the API or the SSH terminal through the browser.
test('sameOrigin accepts the Center\'s own page and non-browser clients', () => {
  assert.strictEqual(sameOrigin(req('http://localhost:3000', 'localhost:3000')), true);
  assert.strictEqual(sameOrigin(req('http://192.168.1.5:3000', '192.168.1.5:3000')), true);
  assert.strictEqual(sameOrigin(req(undefined, 'localhost:3000')), true); // curl, same-origin GET
});

test('sameOrigin refuses other sites and malformed origins', () => {
  assert.strictEqual(sameOrigin(req('https://evil.example', 'localhost:3000')), false);
  assert.strictEqual(sameOrigin(req('http://localhost:3001', 'localhost:3000')), false);
  assert.strictEqual(sameOrigin(req('null', 'localhost:3000')), false);
  assert.strictEqual(sameOrigin(req('not a url', 'localhost:3000')), false);
  assert.strictEqual(sameOrigin(req('http://localhost:3000', undefined)), false);
});
