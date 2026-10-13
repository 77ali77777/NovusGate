const test = require('node:test');
const assert = require('node:assert');
const { endWithError } = require('../lib/sse');

function fakeRes(headersSent) {
  return {
    headersSent,
    chunks: [],
    statusCode: 200,
    body: undefined,
    ended: false,
    write(chunk) { this.chunks.push(chunk); return true; },
    end() { this.ended = true; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; this.ended = true; return this; },
  };
}

const event = (chunk) => JSON.parse(chunk.replace(/^data: /, ''));

test('after SSE headers are flushed the error is sent as stream events', () => {
  const res = fakeRes(true);
  endWithError(res, new Error('All configured authentication methods failed'));
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.chunks.length, 2);
  assert.deepStrictEqual(event(res.chunks[0]), { text: '[ERROR] All configured authentication methods failed\n', stderr: true });
  assert.deepStrictEqual(event(res.chunks[1]), { done: true, success: false });
  assert.ok(res.ended);
});

test('before headers are sent it answers with 500 JSON', () => {
  const res = fakeRes(false);
  endWithError(res, new Error('boom'));
  assert.strictEqual(res.statusCode, 500);
  assert.deepStrictEqual(res.body, { error: 'boom' });
  assert.strictEqual(res.chunks.length, 0);
});

test('non-Error values are reported as text', () => {
  const res = fakeRes(true);
  endWithError(res, 'timeout');
  assert.deepStrictEqual(event(res.chunks[0]), { text: '[ERROR] timeout\n', stderr: true });
});
