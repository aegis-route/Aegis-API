/**
 * ==============================================================================
 * PM2 PRODUCTION ECOSYSTEM CONFIGURATION (ecosystem.config.cjs)
 * ==============================================================================
 * 
 * Usage:
 *   pm2 start ecosystem.config.cjs
 *   pm2 restart ecosystem.config.cjs
 *   pm2 logs aegis-api
 *   pm2 monit
 */

module.exports = {
  apps: [
    {
      name: 'aegis-api',
      script: './src/server.js',
      cwd: './',
      instances: 1, // 1 instance is ideal for in-memory MMDB cache and auto-sync scheduler
      autorestart: true,
      watch: false,
      max_memory_restart: '800M',
      env: {
        NODE_ENV: 'production'
      },
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      error_file: './logs/pm2-error.log',
      out_file: './logs/pm2-out.log',
      merge_logs: true,
      time: true
    }
  ]
};
