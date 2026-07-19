const test = require('node:test');
const assert = require('node:assert/strict');
const { sumDecisionPrefix, percent, shortId } = require('../renderer/lib.js');

test('groups every allowed and denied decision variant', () => {
  const decisions = {
    allowed: 8,
    allowed_execution_failed: 1,
    denied: 3,
    denied_auto_contained: 2,
    denied_quarantined: 1
  };
  assert.equal(sumDecisionPrefix(decisions, 'allowed'), 9);
  assert.equal(sumDecisionPrefix(decisions, 'denied'), 6);
});

test('percent is safe for empty datasets', () => {
  assert.equal(percent(0, 0), 0);
  assert.equal(percent(3, 4), 75);
});

test('short ids preserve small values and truncate long values', () => {
  assert.equal(shortId('abc'), 'abc');
  assert.equal(shortId('abcdefghijklmnop', 6), 'abcdef…');
});
