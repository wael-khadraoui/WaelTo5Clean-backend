import jwt from 'jsonwebtoken';
import { getPool } from '../app/src/db.js';

/** Verify JWT, then load current user from DB (role may change without a new token). */
export async function requireAuth(req, res, next) {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    return res.status(500).json({ error: 'Server misconfiguration' });
  }
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
    const pool = getPool();
    const { rows } = await pool.query(
      `SELECT id, email, role FROM users WHERE id = $1::uuid`,
      [payload.sub]
    );
    if (!rows[0]) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const u = rows[0];
    req.user = { id: u.id, role: u.role, email: u.email };
    next();
  } catch (e) {
    if (e && (e.name === 'JsonWebTokenError' || e.name === 'TokenExpiredError')) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
    return next(e);
  }
}

/**
 * Attach user if token present; continue as guest if not.
 */
export function optionalAuth(req, res, next) {
  const secret = process.env.JWT_SECRET;
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token || !secret) {
    return next();
  }
  try {
    const payload = jwt.verify(token, secret, { algorithms: ['HS256'] });
    req.user = { id: payload.sub, role: payload.role, email: payload.email };
  } catch {
    /* ignore */
  }
  next();
}

/**
 * Require an authenticated user whose role is one of the allowed values.
 */
export function requireRoles(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}
