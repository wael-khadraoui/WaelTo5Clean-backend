/**
 * Central error handling — avoids leaking stack traces in production.
 */
export function notFoundHandler(req, res) {
  res.status(404).json({ error: 'Not found' });
}

export function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    return next(err);
  }
  if (err.code === '22P02') {
    return res.status(400).json({ error: 'Invalid id' });
  }
  const status = err.statusCode || err.status || 500;
  const isProd = process.env.NODE_ENV === 'production';
  const body = {
    error: isProd && status === 500 ? 'Internal server error' : err.message || 'Error',
  };
  if (!isProd && err.stack) {
    body.stack = err.stack;
  }
  res.status(status).json(body);
}
