import { Router } from 'express';
import { getPool } from '../db.js';
import { requireAuth, requireRoles } from '../../../middleware/index.js';
import { userPublicFromRow } from '../lib/rows.js';
import { isUuid } from '../lib/validate.js';

const router = Router();

router.use(requireAuth);

router.get('/', requireRoles('admin', 'monitor'), async (req, res, next) => {
  try {
    const pool = getPool();
    const { rows } = await pool.query(
      `SELECT id, email, name, role, phone, photo_url, distance_display_mode, language, points, created_at
       FROM users
       ORDER BY email ASC`
    );
    res.json({ users: rows.map(userPublicFromRow) });
  } catch (e) {
    next(e);
  }
});

router.get('/delivery-guys', requireRoles('admin', 'monitor'), async (req, res, next) => {
  try {
    const pool = getPool();
    const { rows } = await pool.query(
      `SELECT id, email, name, role, phone, photo_url, distance_display_mode, language, points, created_at
       FROM users
       WHERE role = 'delivery_guy'
       ORDER BY name NULLS LAST, email ASC`
    );
    res.json({ users: rows.map(userPublicFromRow) });
  } catch (e) {
    next(e);
  }
});

router.patch('/:id/role', requireRoles('admin'), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const newRole = req.body?.role;
    const allowed = ['user', 'delivery_guy', 'monitor', 'admin'];
    if (!allowed.includes(newRole)) {
      return res.status(400).json({ success: false, error: 'Invalid role' });
    }
    if (String(req.params.id) === String(req.user.id) && newRole !== 'admin') {
      return res.status(400).json({ success: false, error: 'Cannot demote yourself' });
    }
    const pool = getPool();
    const { rowCount } = await pool.query(
      `UPDATE users SET role = $2, updated_at = NOW() WHERE id = $1::uuid`,
      [req.params.id, newRole]
    );
    if (rowCount === 0) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

export default router;
