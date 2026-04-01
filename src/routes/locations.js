import { Router } from 'express';
import { getPool } from '../db.js';
import { requireAuth, requireRoles } from '../../../middleware/index.js';
import { isUuid } from '../lib/validate.js';

const router = Router();

const mapRoles = requireRoles('admin', 'monitor', 'delivery_guy');

router.use(requireAuth);

function assertLatLng(lat, lng) {
  const la = Number(lat);
  const ln = Number(lng);
  if (!Number.isFinite(la) || !Number.isFinite(ln)) {
    const err = new Error('latitude and longitude must be numbers');
    err.statusCode = 400;
    throw err;
  }
  if (la < -90 || la > 90 || ln < -180 || ln > 180) {
    const err = new Error('Coordinates out of range');
    err.statusCode = 400;
    throw err;
  }
}

router.post('/me', mapRoles, async (req, res, next) => {
  try {
    const { latitude, longitude } = req.body || {};
    if (latitude == null || longitude == null) {
      return res.status(400).json({ success: false, error: 'latitude and longitude required' });
    }
    assertLatLng(latitude, longitude);

    const pool = getPool();
    const { rows: u } = await pool.query(`SELECT name, email FROM users WHERE id = $1::uuid`, [
      req.user.id,
    ]);
    const { rows: pos } = await pool.query(
      `SELECT body FROM delivery_positions WHERE user_id = $1::uuid`,
      [req.user.id]
    );
    const prev = pos[0]?.body && typeof pos[0].body === 'object' ? pos[0].body : {};
    const ts = new Date().toISOString();
    const point = { latitude: Number(latitude), longitude: Number(longitude), timestamp: ts };
    const trajectory = [...(prev.trajectory || []), point].slice(-100);
    const body = {
      name: u[0]?.name || 'Unknown',
      email: u[0]?.email || '',
      location: point,
      trajectory,
      lastSeen: ts,
    };
    await pool.query(
      `INSERT INTO delivery_positions (user_id, body, updated_at)
       VALUES ($1::uuid, $2::jsonb, NOW())
       ON CONFLICT (user_id) DO UPDATE SET body = $2::jsonb, updated_at = NOW()`,
      [req.user.id, JSON.stringify(body)]
    );
    res.json({ success: true });
  } catch (e) {
    if (e.statusCode) {
      return res.status(e.statusCode).json({ success: false, error: e.message });
    }
    next(e);
  }
});

router.get('/active', mapRoles, async (req, res, next) => {
  try {
    const pool = getPool();
    const { rows } = await pool.query(`SELECT user_id, body FROM delivery_positions`);
    const now = Date.now();
    const deliveryGuys = [];
    for (const row of rows) {
      const data = row.body && typeof row.body === 'object' ? row.body : {};
      const lastSeen = data.lastSeen ? new Date(data.lastSeen) : null;
      const isActive = lastSeen && now - lastSeen.getTime() < 30 * 60 * 1000;
      if (isActive && data.location?.latitude != null && data.location?.longitude != null) {
        deliveryGuys.push({
          id: String(row.user_id),
          name: data.name || 'Unknown',
          email: data.email || '',
          location: data.location,
          trajectory: data.trajectory || [],
          lastSeen: data.lastSeen,
        });
      }
    }
    res.json({ deliveryGuys });
  } catch (e) {
    next(e);
  }
});

router.get('/:userId', mapRoles, async (req, res, next) => {
  try {
    if (!isUuid(req.params.userId)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const isSelf = String(req.params.userId) === String(req.user.id);
    const isStaff = req.user.role === 'admin' || req.user.role === 'monitor';
    if (!isSelf && !isStaff) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const pool = getPool();
    const { rows } = await pool.query(
      `SELECT body FROM delivery_positions WHERE user_id = $1::uuid`,
      [req.params.userId]
    );
    const loc = rows[0]?.body?.location;
    if (loc?.latitude != null && loc?.longitude != null) {
      return res.json({
        location: { latitude: loc.latitude, longitude: loc.longitude },
      });
    }
    res.json({ location: null });
  } catch (e) {
    next(e);
  }
});

export default router;
