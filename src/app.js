import express from 'express';
import dotenv from 'dotenv';
import { securityMiddleware, notFoundHandler, errorHandler } from '../../middleware/index.js';
import authRoutes from './routes/auth.js';
import missionRoutes from './routes/missions.js';
import userRoutes from './routes/users.js';
import clientRoutes from './routes/clients.js';
import restaurantRoutes from './routes/restaurants.js';
import settingsRoutes from './routes/settings.js';
import locationRoutes from './routes/locations.js';
import placesRoutes from './routes/places.js';

dotenv.config();

export function createApp() {
  const app = express();
  const corsOrigin = process.env.CORS_ORIGIN || 'http://localhost:5173';

  app.set('trust proxy', 1);
  app.use(express.json({ limit: '2mb' }));

  for (const mw of securityMiddleware({ corsOrigin })) {
    app.use(mw);
  }

  app.get('/api/health', (req, res) => {
    res.json({ ok: true });
  });

  // Strict limit only on login/register (see auth routes). Do not rate-limit GET/PATCH /me — the UI calls /me often.
  app.use('/api/auth', authRoutes);
  app.use('/api/missions', missionRoutes);
  app.use('/api/users', userRoutes);
  app.use('/api/clients', clientRoutes);
  app.use('/api/restaurants', restaurantRoutes);
  app.use('/api/settings', settingsRoutes);
  app.use('/api/locations', locationRoutes);
  app.use('/api/places', placesRoutes);

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
