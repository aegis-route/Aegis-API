import crypto from 'node:crypto';
import { syncService } from '../services/sync.service.js';
import { geoService } from '../services/geo.service.js';
import { config } from '../config.js';

export async function syncRoutes(fastify, options) {
  // Service health and status
  fastify.get('/status', async (req, reply) => {
    const geoStatus = geoService.getStatus();
    const syncStatus = await syncService.getStatus();

    return {
      success: true,
      uptime: process.uptime(),
      databases: geoStatus,
      sync: syncStatus
    };
  });

  // Health check endpoint
  fastify.get('/health', async () => {
    return { status: 'ok', timestamp: new Date().toISOString() };
  });

  // Manual trigger sync endpoint (Protected)
  fastify.post('/sync', async (req, reply) => {
    // Enforce configured sync key
    if (!config.syncApiKey || config.syncApiKey.trim().length === 0) {
      reply.status(403);
      return {
        success: false,
        error: 'Manual sync is disabled on this server. Configure SYNC_API_KEY in .env.'
      };
    }

    const headerKey = req.headers['x-sync-key'];
    const authHeader = req.headers['authorization'];
    const bearerKey = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const providedKey = String(headerKey || bearerKey || '');

    const keyBuf = Buffer.from(providedKey);
    const expectedBuf = Buffer.from(config.syncApiKey);

    if (keyBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(keyBuf, expectedBuf)) {
      reply.status(401);
      return {
        success: false,
        error: 'Unauthorized. Provide valid X-Sync-Key header or Bearer token.'
      };
    }

    const force = req.query?.force === 'true' || req.body?.force === true;

    try {
      const result = await syncService.sync(force);
      return result;
    } catch (err) {
      reply.status(500);
      return {
        success: false,
        error: err.message
      };
    }
  });
}
