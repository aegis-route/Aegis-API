import { geoService } from '../services/geo.service.js';
import { formatService } from '../services/format.service.js';

const ALLOWED_TYPES = new Set(['asn', 'city', 'country', 'all']);

/**
 * Extract real client IP from Fastify request (Cloudflare, Reverse Proxy, Direct)
 */
/**
 * Extract and validate real client IP from Fastify request (Cloudflare, Reverse Proxy, Direct)
 */
function getClientIp(req) {
  const candidates = [
    req.headers['cf-connecting-ip'],
    req.headers['x-real-ip'],
    typeof req.headers['x-forwarded-for'] === 'string' ? req.headers['x-forwarded-for'].split(',')[0] : null
  ];

  for (const candidate of candidates) {
    if (candidate) {
      const trimmed = String(candidate).trim();
      if (geoService.isValidIp(trimmed)) {
        return trimmed;
      }
    }
  }

  const rawIp = typeof req.ip === 'string' ? req.ip.trim() : '';
  return geoService.isValidIp(rawIp) ? rawIp : '127.0.0.1';
}

export async function geoRoutes(fastify, options) {
  // Silent handler for browser favicon requests
  fastify.get('/favicon.ico', async (req, reply) => {
    return reply.status(204).send();
  });

  // Query standardized schema (forms.txt) for given IP: /info/:ip
  fastify.get('/info/:ip', async (req, reply) => {
    const { ip } = req.params;
    try {
      if (!geoService.isValidIp(ip)) {
        reply.status(400);
        return { success: false, error: `Invalid IP address '${ip}'` };
      }
      const data = await formatService.format(ip, {
        enrich: req.query?.enrich !== 'false'
      });
      return data;
    } catch (err) {
      reply.status(500);
      return { success: false, error: err.message, ip };
    }
  });

  // Query standardized schema (forms.txt) for caller IP: /info
  fastify.get('/info', async (req, reply) => {
    const ip = getClientIp(req);
    try {
      if (!geoService.isValidIp(ip)) {
        reply.status(400);
        return { success: false, error: 'Unable to determine a valid client IP address' };
      }
      const data = await formatService.format(ip, {
        enrich: req.query?.enrich !== 'false'
      });
      return data;
    } catch (err) {
      reply.status(500);
      return { success: false, error: err.message, ip };
    }
  });

  // Query raw MMDB data for caller IP: /me
  fastify.get('/me', async (req, reply) => {
    const ip = getClientIp(req);
    try {
      if (!geoService.isValidIp(ip)) {
        reply.status(400);
        return { success: false, error: 'Unable to determine a valid client IP address' };
      }
      return geoService.lookupAll(ip);
    } catch (err) {
      reply.status(err.statusCode || 500);
      return { success: false, error: err.message, ip };
    }
  });
  // Query all databases for given IP: /all/:ip
  fastify.get('/all/:ip', async (req, reply) => {
    const { ip } = req.params;
    try {
      return geoService.lookupAll(ip);
    } catch (err) {
      reply.status(err.statusCode || 500);
      return { success: false, error: err.message, ip };
    }
  });

  // Query specific type for caller IP: /:type (e.g. /asn, /city, /country)
  fastify.get('/:type', async (req, reply) => {
    const { type } = req.params;
    const lowerType = type.toLowerCase();

    if (!ALLOWED_TYPES.has(lowerType)) {
      reply.status(404);
      return {
        success: false,
        error: `Route not found. Valid types are 'asn', 'city', 'country', 'all', or use '/info'.`
      };
    }

    const ip = getClientIp(req);
    try {
      if (lowerType === 'all') {
        return geoService.lookupAll(ip);
      }
      return geoService.lookup(lowerType, ip);
    } catch (err) {
      reply.status(err.statusCode || 500);
      return { success: false, error: err.message, ip, type: lowerType };
    }
  });

  // Query specific type for specific IP: /:type/:ip (e.g. /asn/8.8.8.8, /city/1.1.1.1)
  fastify.get('/:type/:ip', async (req, reply) => {
    const { type, ip } = req.params;
    const lowerType = type.toLowerCase();

    if (!ALLOWED_TYPES.has(lowerType)) {
      reply.status(404);
      return {
        success: false,
        error: `Route not found. Valid types are 'asn', 'city', 'country', 'all', or use '/info/:ip'.`
      };
    }

    try {
      if (lowerType === 'all') {
        return geoService.lookupAll(ip);
      }
      return geoService.lookup(lowerType, ip);
    } catch (err) {
      reply.status(err.statusCode || 500);
      return { success: false, error: err.message, ip, type: lowerType };
    }
  });
}
