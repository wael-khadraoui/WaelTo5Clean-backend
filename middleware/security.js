import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

/** Stricter limit for login/register (mount on /api/auth only in backend). */
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication attempts' },
});

/**
 * Build CORS `origin` option: single string, or dynamic allow-list from comma-separated env.
 */
export function buildCorsOrigin(corsOrigin) {
  const raw = (corsOrigin || '').trim();
  const list = raw.split(',').map((s) => s.trim()).filter(Boolean);
  if (list.length === 0) return 'http://localhost:5173';
  if (list.length === 1) return list[0];
  return (origin, cb) => {
    if (!origin || list.includes(origin)) {
      cb(null, true);
    } else {
      cb(null, false);
    }
  };
}

/**
 * Default API security stack.
 * @param {{ corsOrigin: string }} opts
 */
export function securityMiddleware({ corsOrigin }) {
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 400,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests' },
  });

  return [
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    }),
    cors({
      origin: buildCorsOrigin(corsOrigin),
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      maxAge: 600,
    }),
    apiLimiter,
  ];
}
