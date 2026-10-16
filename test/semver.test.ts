import { test } from 'node:test';
import assert from 'node:assert/strict';
import { compare, satisfies } from '../src/modules/registry/semver.js';

test('compare orders releases and prereleases', () => {
  assert.ok(compare('1.14.1', '1.14.0') > 0);
  assert.ok(compare('6.0.0-rc.1', '6.0.0') < 0);
  assert.ok(compare('6.0.0-beta.4', '6.0.0-rc.1') < 0);
  assert.ok(compare('1.10.0', '1.9.9') > 0);
});

test('satisfies handles the range forms agents pass', () => {
  assert.ok(satisfies('5.6.0', '^5.0.0'));
  assert.ok(!satisfies('6.0.0', '^5.0.0'));
  assert.ok(satisfies('1.14.0', '<1.14.1'));
  assert.ok(!satisfies('1.14.1', '<1.14.1'));
  assert.ok(satisfies('1.2.9', '~1.2.0'));
  assert.ok(!satisfies('1.3.0', '~1.2.0'));
  assert.ok(satisfies('1.9.0', '^1.2'));
  assert.ok(satisfies('2.4.1', '2.x'));
  assert.ok(satisfies('3.0.0', '*'));
  assert.ok(!satisfies('3.0.0-beta.1', '*'));
  assert.ok(satisfies('0.30.3', '>=0.30.0 <0.31.0'));
});
