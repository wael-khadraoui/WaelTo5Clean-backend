import { Router } from 'express';
import { getPool } from '../db.js';
import { requireAuth, requireRoles } from '../../../middleware/index.js';
import { restaurantFromRow } from '../lib/rows.js';
import { isUuid } from '../lib/validate.js';

const router = Router();
const write = requireRoles('admin', 'monitor');
const readRestaurants = requireRoles('admin', 'monitor');

router.use(requireAuth);

router.get('/search', readRestaurants, async (req, res, next) => {
  try {
    const raw = (req.query.q || '').trim();
    const searchLower = raw.toLowerCase();
    const pool = getPool();
    const { rows } = await pool.query(
      `SELECT * FROM restaurants ORDER BY created_at DESC LIMIT 2000`
    );
    if (raw.length < 2) {
      return res.json({ restaurants: [] });
    }
    const matches = rows
      .map(restaurantFromRow)
      .filter((r) => {
        const name = (r.name || '').toLowerCase();
        const addr = (r.address || '').toLowerCase();
        return name.includes(searchLower) || addr.includes(searchLower);
      })
      .slice(0, 10);
    res.json({ restaurants: matches });
  } catch (e) {
    next(e);
  }
});

router.get('/', readRestaurants, async (req, res, next) => {
  try {
    const pool = getPool();
    const { rows } = await pool.query(
      `SELECT * FROM restaurants ORDER BY created_at DESC LIMIT 2000`
    );
    res.json({ restaurants: rows.map(restaurantFromRow) });
  } catch (e) {
    next(e);
  }
});

router.post('/', write, async (req, res, next) => {
  try {
    const data = req.body || {};
    const now = new Date().toISOString();
    const body = { ...data, createdAt: data.createdAt || now, updatedAt: now };
    delete body.id;
    const pool = getPool();
    const { rows } = await pool.query(
      `INSERT INTO restaurants (body) VALUES ($1::jsonb) RETURNING *`,
      [JSON.stringify(body)]
    );
    res.status(201).json({ success: true, restaurant: restaurantFromRow(rows[0]) });
  } catch (e) {
    next(e);
  }
});

router.patch('/:id', write, async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const pool = getPool();
    const { rows } = await pool.query(`SELECT * FROM restaurants WHERE id = $1::uuid`, [
      req.params.id,
    ]);
    if (!rows[0]) return res.status(404).json({ success: false, error: 'Not found' });
    const prev = rows[0].body && typeof rows[0].body === 'object' ? rows[0].body : {};
    const now = new Date().toISOString();
    const nextBody = { ...prev, ...req.body, updatedAt: now };
    await pool.query(
      `UPDATE restaurants SET body = $2::jsonb, updated_at = NOW() WHERE id = $1::uuid`,
      [req.params.id, JSON.stringify(nextBody)]
    );
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

router.delete('/:id', write, async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const pool = getPool();
    await pool.query(`DELETE FROM restaurants WHERE id = $1::uuid`, [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

export default router;
