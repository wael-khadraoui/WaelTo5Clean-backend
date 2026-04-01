import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requireAuth } from '../../../middleware/index.js';

const router = Router();

const searchLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many place searches' },
});

/**
 * Proxy Google Places API (New) searchText so the API key stays on the server.
 * Authenticated users only; rate-limited per IP.
 */
router.post('/search-text', requireAuth, searchLimiter, async (req, res, next) => {
  try {
    const apiKey = process.env.GOOGLE_PLACES_API_KEY;
    if (!apiKey?.trim()) {
      return res.status(503).json({ error: 'Place search is not configured on the server' });
    }

    const textQuery = String(req.body?.textQuery || '').trim();
    if (textQuery.length < 2) {
      return res.status(400).json({ error: 'textQuery must be at least 2 characters' });
    }

    const regionCode = String(req.body?.regionCode || 'TN').trim().slice(0, 2) || 'TN';
    const maxResultCount = Math.min(10, Math.max(1, Number(req.body?.maxResultCount) || 10));

    const requestBody = {
      textQuery,
      regionCode,
      maxResultCount,
    };

    const response = await fetch('https://places.googleapis.com/v1/places:searchText', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Goog-Api-Key': apiKey,
        'X-Goog-FieldMask': 'places.id,places.displayName,places.formattedAddress,places.location',
      },
      body: JSON.stringify(requestBody),
    });

    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      return res.status(502).json({ error: 'Invalid response from place search' });
    }

    if (!response.ok) {
      return res.status(502).json({ error: 'Place search failed' });
    }

    res.json(data);
  } catch (e) {
    next(e);
  }
});

export default router;
