/**
 * Shared middleware layer (cross-cutting concerns).
 * Imported by the backend only — keeps auth, limits, and errors in one place.
 */

export { securityMiddleware, authRateLimiter, buildCorsOrigin } from './security.js';
export { notFoundHandler, errorHandler } from './errors.js';
export { requireAuth, optionalAuth, requireRoles } from './auth.js';
