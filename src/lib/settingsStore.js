import { getPool } from '../db.js';

const DEFAULT_SYSTEM = {
  maxMinutes: 60,
  orangeThreshold: 20,
  redThreshold: 5,
  pointsOnTime: 10,
  pointsLowTime: 20,
  pointsDeducted: 5,
};

export async function getSystemParameters() {
  const pool = getPool();
  const { rows } = await pool.query(
    `SELECT value FROM app_settings WHERE key = 'system_parameters' LIMIT 1`
  );
  if (!rows[0]?.value) return { ...DEFAULT_SYSTEM };
  return { ...DEFAULT_SYSTEM, ...rows[0].value };
}

export async function getDeliveryFeeRulesArray() {
  const pool = getPool();
  const { rows } = await pool.query(
    `SELECT value FROM app_settings WHERE key = 'delivery_fees' LIMIT 1`
  );
  const rules = rows[0]?.value?.rules;
  return Array.isArray(rules) ? rules : [];
}

export async function applyCompletionPoints(missionRow) {
  const pool = getPool();
  const body = missionRow.body && typeof missionRow.body === 'object' ? missionRow.body : {};
  if (body.pointsAwarded != null) return { skipped: true };

  const assignedTo = missionRow.assigned_to;
  if (!assignedTo) return { skipped: true };

  const params = await getSystemParameters();
  const createdAt = new Date(body.createdAt || missionRow.created_at);
  const completedAt = new Date(body.completedAt || Date.now());
  if (Number.isNaN(createdAt.getTime()) || Number.isNaN(completedAt.getTime())) {
    return { skipped: true };
  }

  const elapsedMs = completedAt - createdAt;
  const elapsedMinutes = Math.floor(elapsedMs / 60000);

  let pointsChange = 0;
  const timeRemaining = params.maxMinutes - elapsedMinutes;
  const percentageRemaining = (timeRemaining / params.maxMinutes) * 100;

  let wasLowTimeWhenPickedUp = false;
  if (body.assignedAt) {
    const assignedAt = new Date(body.assignedAt);
    const timeAtAssignment = Math.floor((assignedAt - createdAt) / 60000);
    const timeRemainingAtAssignment = params.maxMinutes - timeAtAssignment;
    const percentageAtAssignment = (timeRemainingAtAssignment / params.maxMinutes) * 100;
    wasLowTimeWhenPickedUp = percentageAtAssignment <= params.orangeThreshold;
  }

  if (elapsedMinutes > params.maxMinutes) {
    pointsChange = -params.pointsDeducted;
  } else if (wasLowTimeWhenPickedUp) {
    pointsChange = params.pointsLowTime;
  } else {
    pointsChange = params.pointsOnTime;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows: urows } = await client.query(
      `SELECT points FROM users WHERE id = $1 FOR UPDATE`,
      [assignedTo]
    );
    const currentPoints = urows[0]?.points ?? 0;
    const newPoints = Math.max(0, currentPoints + pointsChange);
    await client.query(`UPDATE users SET points = $1, updated_at = NOW() WHERE id = $2`, [
      newPoints,
      assignedTo,
    ]);
    await client.query(
      `UPDATE missions SET body = body || $1::jsonb, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify({ pointsAwarded: pointsChange }), missionRow.id]
    );
    await client.query('COMMIT');
    return { pointsChange };
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}
