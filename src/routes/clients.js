import { Router } from 'express';
import { getPool } from '../db.js';
import { requireAuth, requireRoles } from '../../../middleware/index.js';
import { clientFromRow } from '../lib/rows.js';
import { isUuid } from '../lib/validate.js';

const router = Router();

router.use(requireAuth);
const write = requireRoles('admin', 'monitor');

function mergeLocations(existingLocations, newLocations) {
  const merged = [...(existingLocations || [])];
  for (const newLoc of newLocations || []) {
    const idx = merged.findIndex(
      (existing) =>
        existing.address &&
        newLoc.address &&
        existing.address.trim().toLowerCase() === newLoc.address.trim().toLowerCase()
    );
    if (idx >= 0) merged[idx] = newLoc;
    else merged.push(newLoc);
  }
  return merged;
}

const readClients = requireRoles('admin', 'monitor');

router.get('/', readClients, async (req, res, next) => {
  try {
    const pool = getPool();
    const q = (req.query.search || '').trim().toLowerCase();
    const { rows } = await pool.query(
      `SELECT * FROM clients ORDER BY updated_at DESC NULLS LAST, created_at DESC LIMIT 2000`
    );
    let list = rows.map(clientFromRow);
    if (q.length >= 2) {
      list = list.filter(
        (c) =>
          (c.name && c.name.toLowerCase().includes(q)) ||
          (c.phone && String(c.phone).includes(req.query.search.trim()))
      );
      list = list.slice(0, 10);
    }
    res.json({ clients: q.length >= 2 ? list : rows.map(clientFromRow) });
  } catch (e) {
    next(e);
  }
});

router.post('/', write, async (req, res, next) => {
  try {
    const clientData = req.body || {};
    const phone = clientData.phone;
    if (!phone) {
      return res.status(400).json({ success: false, error: 'phone required' });
    }
    const pool = getPool();
    const { rows: existing } = await pool.query(
      `SELECT * FROM clients WHERE phone = $1 LIMIT 1`,
      [phone]
    );
    const now = new Date().toISOString();

    if (existing[0]) {
      const row = existing[0];
      const body = row.body && typeof row.body === 'object' ? { ...row.body } : {};
      const mergedLocations = mergeLocations(body.locations || [], clientData.locations || []);
      const newBody = {
        ...body,
        name: clientData.name,
        phone,
        locations: mergedLocations,
        updatedAt: now,
      };
      await pool.query(
        `UPDATE clients SET body = $2::jsonb, updated_at = NOW() WHERE id = $1::uuid`,
        [row.id, JSON.stringify(newBody)]
      );
      return res.json({ success: true, clientId: row.id, isNew: false });
    }

    const newBody = {
      name: clientData.name,
      phone,
      locations: clientData.locations || [],
      createdAt: now,
      updatedAt: now,
    };
    const { rows } = await pool.query(
      `INSERT INTO clients (phone, body) VALUES ($1, $2::jsonb) RETURNING id`,
      [phone, JSON.stringify(newBody)]
    );
    res.status(201).json({ success: true, clientId: rows[0].id, isNew: true });
  } catch (e) {
    next(e);
  }
});

router.patch(
  '/:id/location',
  requireAuth,
  requireRoles('admin', 'monitor', 'delivery_guy'),
  async (req, res, next) => {
    try {
      const { address, location } = req.body || {};
      if (!address || !location) {
        return res.status(400).json({ success: false, error: 'address and location required' });
      }
      const pool = getPool();
      if (!isUuid(req.params.id)) {
        return res.status(400).json({ success: false, error: 'Invalid id' });
      }
      const { rows } = await pool.query(`SELECT * FROM clients WHERE id = $1::uuid`, [req.params.id]);
      if (!rows[0]) return res.status(404).json({ success: false, error: 'Client not found' });
      const row = rows[0];
      const body = row.body && typeof row.body === 'object' ? { ...row.body } : {};
      const locations = body.locations || [];
      const addressLower = String(address).trim().toLowerCase();
      const idx = locations.findIndex(
        (loc) => loc.address && loc.address.trim().toLowerCase() === addressLower
      );
      const entry = {
        latitude: location.latitude,
        longitude: location.longitude,
      };
      if (idx >= 0) {
        locations[idx] = {
          ...locations[idx],
          location: entry,
        };
      } else {
        locations.push({
          address: String(address).trim(),
          location: entry,
        });
      }
      const now = new Date().toISOString();
      const newBody = { ...body, locations, updatedAt: now };
      await pool.query(
        `UPDATE clients SET body = $2::jsonb, updated_at = NOW() WHERE id = $1::uuid`,
        [req.params.id, JSON.stringify(newBody)]
      );
      res.json({ success: true });
    } catch (e) {
      next(e);
    }
  }
);

router.patch('/:id', write, async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const pool = getPool();
    const { rows } = await pool.query(`SELECT * FROM clients WHERE id = $1::uuid`, [req.params.id]);
    if (!rows[0]) return res.status(404).json({ success: false, error: 'Not found' });
    const row = rows[0];
    const body = row.body && typeof row.body === 'object' ? { ...row.body } : {};
    const now = new Date().toISOString();
    const nextBody = { ...body, ...req.body, updatedAt: now };
    const phone = nextBody.phone != null ? nextBody.phone : row.phone;
    await pool.query(
      `UPDATE clients SET phone = $2, body = $3::jsonb, updated_at = NOW() WHERE id = $1::uuid`,
      [req.params.id, phone, JSON.stringify(nextBody)]
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
    await pool.query(`DELETE FROM clients WHERE id = $1::uuid`, [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

export default router;
