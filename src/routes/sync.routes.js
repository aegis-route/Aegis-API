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
    // Check API Key
    if (config.syncApiKey) {
      const headerKey = req.headers['x-sync-key'];
      const authHeader = req.headers['authorization'];
      const bearerKey = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      const providedKey = headerKey || bearerKey;

      if (!providedKey || providedKey !== config.syncApiKey) {
        reply.status(401);
        return {
          success: false,
          error: 'Unauthorized. Provide valid X-Sync-Key header or Bearer token.'
        };
      }
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
