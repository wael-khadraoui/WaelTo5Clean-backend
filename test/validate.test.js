import test from 'node:test';
import assert from 'node:assert/strict';
import { assertMissionPatchAllowed } from '../src/lib/validate.js';
import { validateAndNormalizeDeliveryFeeRules } from '../src/lib/deliveryFeeRules.js';

test('admin may keep completed mission status', () => {
  assert.doesNotThrow(() => {
    assertMissionPatchAllowed(
      { id: 'a', role: 'admin' },
      { status: 'completed', assigned_to: 'x' },
      'completed'
    );
  });
});

test('delivery cannot cancel', () => {
  assert.throws(() => {
    assertMissionPatchAllowed(
      { id: 'd1', role: 'delivery_guy' },
      { status: 'assigned', assigned_to: 'd1' },
      'cancelled'
    );
  });
});

test('delivery cannot complete unassigned mission', () => {
  assert.throws(() => {
    assertMissionPatchAllowed(
      { id: 'd1', role: 'delivery_guy' },
      { status: 'pending', assigned_to: null },
      'completed'
    );
  });
});

test('delivery can complete when assigned to self', () => {
  assert.doesNotThrow(() => {
    assertMissionPatchAllowed(
      { id: 'd1', role: 'delivery_guy' },
      { status: 'in_progress', assigned_to: 'd1' },
      'completed'
    );
  });
});

test('delivery fee rules reject non-array', () => {
  const r = validateAndNormalizeDeliveryFeeRules({});
  assert.equal(r.ok, false);
});

test('delivery fee rules normalize valid row', () => {
  const r = validateAndNormalizeDeliveryFeeRules([
    { minDistance: 0, maxDistance: 5, fee: 10 },
    { minDistance: 5, maxDistance: null, fee: 20 },
  ]);
  assert.equal(r.ok, true);
  assert.equal(r.rules[1].maxDistance, null);
});
