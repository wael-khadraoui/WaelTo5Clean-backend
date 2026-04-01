import { Router } from 'express';
import { getPool } from '../db.js';
import { requireAuth, requireRoles } from '../../../middleware/index.js';
import { getDeliveryFeeRulesArray, getSystemParameters } from '../lib/settingsStore.js';
import { validateAndNormalizeDeliveryFeeRules } from '../lib/deliveryFeeRules.js';

const router = Router();

router.use(requireAuth);

router.get('/delivery-fees', requireRoles('admin', 'monitor'), async (req, res, next) => {
  try {
    const rules = await getDeliveryFeeRulesArray();
    res.json({ success: true, rules });
  } catch (e) {
    next(e);
  }
});

router.put('/delivery-fees', requireRoles('admin', 'monitor'), async (req, res, next) => {
  try {
    const parsed = validateAndNormalizeDeliveryFeeRules(req.body?.rules);
    if (!parsed.ok) {
      return res.status(400).json({ success: false, error: parsed.error });
    }
    const pool = getPool();
    await pool.query(
      `INSERT INTO app_settings (key, value, updated_at)
       VALUES ('delivery_fees', $1::jsonb, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $1::jsonb, updated_at = NOW()`,
      [JSON.stringify({ rules: parsed.rules })]
    );
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

router.get(
  '/system-parameters',
  requireRoles('admin', 'monitor', 'delivery_guy'),
  async (req, res, next) => {
    try {
      const params = await getSystemParameters();
      res.json(params);
    } catch (e) {
      next(e);
    }
  }
);

const SYSTEM_PARAM_KEYS = new Set([
  'maxMinutes',
  'orangeThreshold',
  'redThreshold',
  'pointsOnTime',
  'pointsLowTime',
  'pointsDeducted',
]);

const PARAM_BOUNDS = {
  maxMinutes: { min: 1, max: 10080 },
  orangeThreshold: { min: 0, max: 100 },
  redThreshold: { min: 0, max: 100 },
  pointsOnTime: { min: 0, max: 10000 },
  pointsLowTime: { min: 0, max: 10000 },
  pointsDeducted: { min: 0, max: 10000 },
};

router.put('/system-parameters', requireRoles('admin', 'monitor'), async (req, res, next) => {
  try {
    const pool = getPool();
    const current = await getSystemParameters();
    const nextParams = { ...current };
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    for (const key of SYSTEM_PARAM_KEYS) {
      if (body[key] === undefined) continue;
      const n = Number(body[key]);
      const { min, max } = PARAM_BOUNDS[key];
      if (!Number.isFinite(n) || n < min || n > max) {
        return res.status(400).json({ success: false, error: `Invalid ${key}` });
      }
      nextParams[key] = n;
    }
    await pool.query(
      `INSERT INTO app_settings (key, value, updated_at)
       VALUES ('system_parameters', $1::jsonb, NOW())
       ON CONFLICT (key) DO UPDATE SET value = $1::jsonb, updated_at = NOW()`,
      [JSON.stringify(nextParams)]
    );
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

export default router;
