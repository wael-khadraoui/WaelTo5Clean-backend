/** RFC 4122 UUID (case-insensitive). */
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function isUuid(value) {
  return typeof value === 'string' && UUID_RE.test(value);
}

export const MISSION_STATUSES = new Set([
  'pending',
  'assigned',
  'in_progress',
  'completed',
  'cancelled',
]);

/**
 * Enforce who may PATCH mission row → newStatus (defense in depth vs UI).
 */
export function assertMissionPatchAllowed(user, prevRow, newStatus) {
  if (!MISSION_STATUSES.has(newStatus)) {
    const err = new Error('Invalid status');
    err.statusCode = 400;
    throw err;
  }

  const prevStatus = prevRow.status;
  const assigned = prevRow.assigned_to != null ? String(prevRow.assigned_to) : null;
  const uid = String(user.id);
  const isStaff = user.role === 'admin' || user.role === 'monitor';
  const isDelivery = user.role === 'delivery_guy';

  if (isStaff) return;

  if (!isDelivery) {
    const err = new Error('Forbidden');
    err.statusCode = 403;
    throw err;
  }

  if (prevStatus === 'completed' || prevStatus === 'cancelled') {
    const err = new Error('Forbidden');
    err.statusCode = 403;
    throw err;
  }

  if (newStatus === 'cancelled') {
    const err = new Error('Forbidden');
    err.statusCode = 403;
    throw err;
  }

  if (newStatus === 'completed' && assigned !== uid) {
    const err = new Error('Forbidden');
    err.statusCode = 403;
    throw err;
  }

  if (newStatus === 'in_progress' && assigned !== uid) {
    const err = new Error('Forbidden');
    err.statusCode = 403;
    throw err;
  }

  if (newStatus === 'assigned' && prevStatus !== 'assigned') {
    const err = new Error('Use the assign endpoint');
    err.statusCode = 400;
    throw err;
  }

  if (newStatus === prevStatus) {
    if (!assigned || assigned === uid) return;
    const err = new Error('Forbidden');
    err.statusCode = 403;
    throw err;
  }

  if (assigned && assigned !== uid) {
    const err = new Error('Forbidden');
    err.statusCode = 403;
    throw err;
  }

  if (!assigned && newStatus !== prevStatus && newStatus !== 'pending') {
    const err = new Error('Pick up the mission before changing its state');
    err.statusCode = 403;
    throw err;
  }

  if (newStatus !== prevStatus) {
    const order = ['pending', 'assigned', 'in_progress', 'completed'];
    const pi = order.indexOf(prevStatus);
    const ni = order.indexOf(newStatus);
    if (ni !== -1 && pi !== -1 && ni < pi) {
      const err = new Error('Forbidden');
      err.statusCode = 403;
      throw err;
    }
  }
}
