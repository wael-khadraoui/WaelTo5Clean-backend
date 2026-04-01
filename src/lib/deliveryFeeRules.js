const MAX_RULES = 200;

/**
 * Normalize and validate delivery fee rules from client JSON.
 * @returns {{ ok: true, rules: object[] } | { ok: false, error: string }}
 */
export function validateAndNormalizeDeliveryFeeRules(raw) {
  if (!Array.isArray(raw)) {
    return { ok: false, error: 'rules must be an array' };
  }
  if (raw.length > MAX_RULES) {
    return { ok: false, error: `At most ${MAX_RULES} rules allowed` };
  }

  const rules = [];
  for (let i = 0; i < raw.length; i++) {
    const r = raw[i];
    if (r == null || typeof r !== 'object') {
      return { ok: false, error: `Rule ${i} must be an object` };
    }
    const minDistance = Number(r.minDistance);
    const maxDistanceRaw = r.maxDistance;
    const maxDistance =
      maxDistanceRaw === null || maxDistanceRaw === undefined || maxDistanceRaw === ''
        ? Infinity
        : Number(maxDistanceRaw);
    const fee = Number(r.fee);

    if (!Number.isFinite(minDistance) || minDistance < 0 || minDistance > 1e6) {
      return { ok: false, error: `Rule ${i}: invalid minDistance` };
    }
    if (maxDistance !== Infinity && (!Number.isFinite(maxDistance) || maxDistance < minDistance)) {
      return { ok: false, error: `Rule ${i}: invalid maxDistance` };
    }
    if (!Number.isFinite(fee) || fee < 0 || fee > 1e7) {
      return { ok: false, error: `Rule ${i}: invalid fee` };
    }

    rules.push({
      minDistance,
      maxDistance: maxDistance === Infinity ? null : maxDistance,
      fee,
    });
  }

  return { ok: true, rules };
}
