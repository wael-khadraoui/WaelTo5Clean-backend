import { Router } from 'express';
import { getPool } from '../db.js';
import { requireAuth, requireRoles } from '../../../middleware/index.js';
import { missionFromRow } from '../lib/rows.js';
import { applyCompletionPoints } from '../lib/settingsStore.js';
import { assertMissionPatchAllowed, isUuid } from '../lib/validate.js';

const router = Router();

function canAccessMission(user, row) {
  if (user.role === 'admin' || user.role === 'monitor') return true;
  if (user.role === 'delivery_guy') {
    return row.assigned_to == null || String(row.assigned_to) === String(user.id);
  }
  return false;
}

router.use(requireAuth);

router.get('/', async (req, res, next) => {
  try {
    const pool = getPool();
    const { role, id } = req.user;
    let result;
    if (role === 'admin' || role === 'monitor') {
      result = await pool.query(
        `SELECT * FROM missions ORDER BY created_at DESC LIMIT 500`
      );
    } else if (role === 'delivery_guy') {
      result = await pool.query(
        `SELECT * FROM missions
         WHERE assigned_to = $1::uuid OR assigned_to IS NULL
         ORDER BY created_at DESC
         LIMIT 500`,
        [id]
      );
    } else {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json({ missions: result.rows.map(missionFromRow) });
  } catch (e) {
    next(e);
  }
});

router.get('/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ error: 'Invalid id' });
    }
    const pool = getPool();
    const { rows } = await pool.query(`SELECT * FROM missions WHERE id = $1::uuid`, [
      req.params.id,
    ]);
    const row = rows[0];
    if (!row) return res.status(404).json({ error: 'Not found' });
    if (!canAccessMission(req.user, row)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json({ mission: missionFromRow(row) });
  } catch (e) {
    next(e);
  }
});

router.post('/', requireRoles('admin', 'monitor'), async (req, res, next) => {
  try {
    const input = req.body || {};
    const pool = getPool();
    const now = new Date().toISOString();
    const hasAssigned = !!input.assignedTo;
    const status = hasAssigned ? 'assigned' : 'pending';
    const assigned_to = input.assignedTo ? String(input.assignedTo) : null;
    const created_by = String(req.user.id);

    const body = { ...input };
    delete body.id;
    body.status = status;
    body.assignedAt = hasAssigned ? now : null;
    body.createdAt = body.createdAt || now;
    body.updatedAt = now;
    body.createdBy = created_by;
    if (assigned_to) body.assignedTo = assigned_to;

    const { rows } = await pool.query(
      `INSERT INTO missions (status, assigned_to, created_by, body)
       VALUES ($1, $2::uuid, $3::uuid, $4::jsonb)
       RETURNING *`,
      [status, assigned_to, created_by, JSON.stringify(body)]
    );
    const m = rows[0];
    res.status(201).json({
      success: true,
      missionId: m.id,
      mission: missionFromRow(m),
    });
  } catch (e) {
    next(e);
  }
});

router.patch('/:id', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const pool = getPool();
    const { rows } = await pool.query(`SELECT * FROM missions WHERE id = $1::uuid`, [
      req.params.id,
    ]);
    const prev = rows[0];
    if (!prev) return res.status(404).json({ success: false, error: 'Mission not found' });
    if (!canAccessMission(req.user, prev)) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const patch = req.body || {};
    const newStatus = patch.status != null ? patch.status : prev.status;
    const { status: _st, ...additional } = patch;

    try {
      assertMissionPatchAllowed(req.user, prev, newStatus);
    } catch (authErr) {
      return res
        .status(authErr.statusCode || 403)
        .json({ success: false, error: authErr.message });
    }

    await pool.query(
      `UPDATE missions
       SET status = $2,
           body = body || $3::jsonb,
           updated_at = NOW()
       WHERE id = $1::uuid`,
      [req.params.id, newStatus, JSON.stringify({ ...additional, updatedAt: new Date().toISOString() })]
    );

    if (newStatus === 'completed' && prev.status !== 'completed') {
      const { rows: after } = await pool.query(`SELECT * FROM missions WHERE id = $1::uuid`, [
        req.params.id,
      ]);
      try {
        await applyCompletionPoints(after[0]);
      } catch (err) {
        console.error('applyCompletionPoints', err);
      }
    }

    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

router.delete('/:id', requireRoles('admin', 'monitor'), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const pool = getPool();
    const { rowCount } = await pool.query(`DELETE FROM missions WHERE id = $1::uuid`, [
      req.params.id,
    ]);
    if (rowCount === 0) {
      return res.status(404).json({ success: false, error: 'Mission not found' });
    }
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

router.post('/:id/assign', async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const deliveryGuyId = req.body?.deliveryGuyId != null ? String(req.body.deliveryGuyId) : null;
    const allowReassign = !!req.body?.allowReassign;
    if (!deliveryGuyId || !isUuid(deliveryGuyId)) {
      return res.status(400).json({ success: false, error: 'Valid deliveryGuyId required' });
    }

    const pool = getPool();
    const { rows } = await pool.query(`SELECT * FROM missions WHERE id = $1::uuid`, [
      req.params.id,
    ]);
    const prev = rows[0];
    if (!prev) return res.status(404).json({ success: false, error: 'Mission not found' });
    if (!canAccessMission(req.user, prev)) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const { rows: assignee } = await pool.query(
      `SELECT id, role FROM users WHERE id = $1::uuid`,
      [deliveryGuyId]
    );
    const assigneeRow = assignee[0];
    const selfAssign = deliveryGuyId === String(req.user.id);
    const assigneeOk =
      assigneeRow &&
      (assigneeRow.role === 'delivery_guy' ||
        (selfAssign && (assigneeRow.role === 'admin' || assigneeRow.role === 'monitor')));
    if (!assigneeOk) {
      return res.status(400).json({
        success: false,
        error: 'Assign to a delivery account, or pick up yourself as admin/monitor',
      });
    }

    const currentAssigned = prev.assigned_to ? String(prev.assigned_to) : null;
    if (!allowReassign && currentAssigned && currentAssigned !== deliveryGuyId) {
      return res.status(400).json({
        success: false,
        error: 'Mission is already assigned to another delivery guy',
      });
    }

    if (req.user.role === 'delivery_guy') {
      if (deliveryGuyId !== String(req.user.id)) {
        return res.status(403).json({ success: false, error: 'Forbidden' });
      }
      if (currentAssigned && currentAssigned !== String(req.user.id)) {
        return res.status(400).json({
          success: false,
          error: 'Mission is already assigned to another delivery guy',
        });
      }
    } else if (req.user.role !== 'admin' && req.user.role !== 'monitor') {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }

    const now = new Date().toISOString();
    const merge = {
      assignedTo: deliveryGuyId,
      assignedAt: now,
      status: 'assigned',
      updatedAt: now,
    };

    await pool.query(
      `UPDATE missions
       SET status = 'assigned',
           assigned_to = $2::uuid,
           body = body || $3::jsonb,
           updated_at = NOW()
       WHERE id = $1::uuid`,
      [req.params.id, deliveryGuyId, JSON.stringify(merge)]
    );

    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

router.post('/:id/points', requireRoles('admin', 'monitor'), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) {
      return res.status(400).json({ success: false, error: 'Invalid id' });
    }
    const pool = getPool();
    const { rows } = await pool.query(`SELECT * FROM missions WHERE id = $1::uuid`, [
      req.params.id,
    ]);
    const row = rows[0];
    if (!row) return res.status(404).json({ success: false, error: 'Mission not found' });
    if (!canAccessMission(req.user, row)) {
      return res.status(403).json({ success: false, error: 'Forbidden' });
    }
    const result = await applyCompletionPoints(row);
    res.json({ success: true, ...result });
  } catch (e) {
    next(e);
  }
});

export default router;
