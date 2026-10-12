import Fastify from 'fastify';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { config } from './config.js';
import { geoRoutes } from './routes/geo.routes.js';
import { syncRoutes } from './routes/sync.routes.js';
import { syncService } from './services/sync.service.js';

async function bootstrap() {
  const app = Fastify({
    logger: true,
    trustProxy: true
  });

  // Security Headers (OWASP)
  await app.register(helmet, {
    contentSecurityPolicy: false // API returns JSON
  });

  // Rate Limiting (Prevents DoS and API quota exhaustion)
  await app.register(rateLimit, {
    max: 120,
    timeWindow: '1 minute',
    allowList: ['127.0.0.1']
  });

  // Enable CORS
  await app.register(cors, {
    origin: true
  });

  // Home / Documentation route
  app.get('/', async () => {
    return {
      name: 'Aegis GeoIP API',
      version: '1.0.0',
      description: 'High-performance GeoLite2 MMDB IP Lookup Service with Auto-Sync',
      endpoints: {
        info: 'GET /info/{ip}       (standardized forms.txt format with full geo, ASN & threat flags)',
        query_type: 'GET /{type}/{ip}  (type: asn, city, country, all)',
        query_client: 'GET /{type}        (queries caller IP address)',
        all_info: 'GET /all/{ip}       (full ASN, City, and Country data)',
        me: 'GET /me             (full Geo data for caller IP)',
        status: 'GET /status         (database & sync status)',
        health: 'GET /health         (healthcheck)',
        sync: 'POST /sync          (trigger sync from upstream, protected)'
      },
      examples: [
        'curl https://<domain>/info/1.1.1.1',
        'curl https://<domain>/info/1.1.1.1?enrich=true',
        'curl https://<domain>/asn/8.8.8.8',
        'curl https://<domain>/city/1.1.1.1',
        'curl https://<domain>/country/9.9.9.9',
        'curl https://<domain>/all/8.8.8.8',
        'curl https://<domain>/me'
      ]
    };
  });

  // Register routes
  await app.register(syncRoutes);
  await app.register(geoRoutes);

  // Global Error Handler
  app.setErrorHandler((error, request, reply) => {
    app.log.error(error);
    const statusCode = error.statusCode || 500;
    reply.status(statusCode).send({
      success: false,
      error: error.message || 'Internal Server Error',
      statusCode
    });
  });

  // Start HTTP Server
  try {
    await app.listen({ port: config.port, host: config.host });
    console.log(`\n🚀 Aegis GeoIP API is running at http://${config.host}:${config.port}`);
    console.log(`📁 Data directory: ${config.dataDir}`);

    // Start auto-sync and scheduler
    syncService.startSchedule();
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }

  // Graceful shutdown
  const signals = ['SIGINT', 'SIGTERM'];
  for (const signal of signals) {
    process.on(signal, async () => {
      console.log(`\n[Server] Received ${signal}, closing gracefully...`);
      syncService.stopSchedule();
      await app.close();
      process.exit(0);
    });
  }
}

bootstrap();
