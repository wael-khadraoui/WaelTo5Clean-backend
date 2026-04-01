import { Router } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { getPool } from '../db.js';
import { requireAuth, authRateLimiter } from '../../../middleware/index.js';
import { userPublicFromRow } from '../lib/rows.js';

const router = Router();
const BCRYPT_ROUNDS = 12;

function signToken(user) {
  const secret = process.env.JWT_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('JWT_SECRET must be set (min 32 chars)');
  }
  return jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
    },
    secret,
    { algorithm: 'HS256', expiresIn: '7d' }
  );
}

router.post('/register', authRateLimiter, async (req, res, next) => {
  try {
    if (process.env.ALLOW_REGISTER === 'false') {
      return res.status(403).json({ error: 'Registration is disabled' });
    }
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const name = String(req.body?.name || '').trim() || null;

    if (!email || !password || password.length < 8) {
      return res.status(400).json({ error: 'Valid email and password (min 8 chars) required' });
    }

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const pool = getPool();
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, role)
       VALUES ($1, $2, $3, 'user')
       RETURNING id, email, name, role, created_at`,
      [email, hash, name]
    );
    const user = result.rows[0];
    const token = signToken(user);
    res.status(201).json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    if (e.code === '23505') {
      return res.status(409).json({ error: 'Email already registered' });
    }
    next(e);
  }
});

router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const pool = getPool();
    const { rows } = await pool.query(
      `SELECT id, email, name, role, phone, photo_url, distance_display_mode, language, points, fcm_token, created_at
       FROM users WHERE id = $1::uuid`,
      [req.user.id]
    );
    const row = rows[0];
    if (!row) return res.status(404).json({ error: 'User not found' });
    res.json({ user: userPublicFromRow(row) });
  } catch (e) {
    next(e);
  }
});

router.patch('/me', requireAuth, async (req, res, next) => {
  try {
    const body = req.body || {};
    const updates = [];
    const values = [];
    let i = 1;

    if (body.name !== undefined) {
      updates.push(`name = $${i++}`);
      values.push(body.name);
    }
    if (body.phone !== undefined) {
      updates.push(`phone = $${i++}`);
      values.push(body.phone);
    }
    if (body.photoURL !== undefined) {
      updates.push(`photo_url = $${i++}`);
      values.push(body.photoURL);
    }
    if (body.distanceDisplayMode !== undefined) {
      updates.push(`distance_display_mode = $${i++}`);
      values.push(body.distanceDisplayMode);
    }
    if (body.language !== undefined) {
      updates.push(`language = $${i++}`);
      values.push(body.language);
    }
    if (body.fcmToken !== undefined) {
      updates.push(`fcm_token = $${i++}`);
      values.push(body.fcmToken);
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, error: 'No valid profile fields provided' });
    }

    updates.push(`updated_at = NOW()`);
    values.push(req.user.id);
    const pool = getPool();
    await pool.query(
      `UPDATE users SET ${updates.join(', ')} WHERE id = $${i}::uuid`,
      values
    );
    res.json({ success: true });
  } catch (e) {
    next(e);
  }
});

router.post('/login', authRateLimiter, async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }
    const pool = getPool();
    const result = await pool.query(
      'SELECT id, email, password_hash, name, role FROM users WHERE email = $1',
      [email]
    );
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = signToken(user);
    res.json({
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role },
    });
  } catch (e) {
    next(e);
  }
});

export default router;
