import Fastify from 'fastify';
import { managementRoutes } from './src/routes/management.routes.js';
import { storeService } from './src/services/store.service.js';

async function runTests() {
  console.log('[Test] Initializing Fastify instance for management routes validation...');

  const app = Fastify({ logger: false });
  await app.register(managementRoutes, { prefix: '/api/v1' });
  await app.register(managementRoutes, { prefix: '/api' });
  await app.register(managementRoutes);

  await app.ready();
  let passed = 0;
  let failed = 0;

  async function assert(desc, testFn) {
    try {
      await testFn();
      console.log(`  ✓ PASS: ${desc}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ FAIL: ${desc}`);
      console.error(`    ${err.message}`);
      failed++;
    }
  }

  console.log('\n--- 1. Testing Firewall & Mitigation Endpoints ---');

  await assert('GET /api/v1/firewall/modules returns 16 modules', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/firewall/modules' });
    const json = JSON.parse(res.body);
    if (!json.success || json.data.length !== 16) {
      throw new Error(`Expected 16 modules, got ${json.data?.length}`);
    }
  });

  await assert('PATCH /api/v1/firewall/modules updates module mode', async () => {
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/v1/firewall/modules',
      payload: { id: 'syn_flood', mode: 'MONITOR' }
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.module.mode !== 'MONITOR') {
      throw new Error(`Failed to update syn_flood to MONITOR: ${res.body}`);
    }
  });

  await assert('POST /api/v1/firewall/bans adds an IP to ban list', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/firewall/bans',
      payload: { ip: '198.51.100.77', reason: 'Automated test ban', country: 'Vietnam', countryCode: 'VN' }
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.ban.ip !== '198.51.100.77') {
      throw new Error(`Failed to ban IP: ${res.body}`);
    }
  });

  await assert('GET /api/v1/firewall/bans retrieves active bans', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/firewall/bans' });
    const json = JSON.parse(res.body);
    if (!json.success || !json.data.some((b) => b.ip === '198.51.100.77')) {
      throw new Error(`Banned IP not found in list: ${res.body}`);
    }
  });

  await assert('DELETE /api/v1/firewall/bans unbans IP', async () => {
    const res = await app.inject({
      method: 'DELETE',
      url: '/api/v1/firewall/bans?ip=198.51.100.77'
    });
    const json = JSON.parse(res.body);
    if (!json.success) {
      throw new Error(`Failed to unban IP: ${res.body}`);
    }
  });

  let createdCidrId = '';
  await assert('POST /api/v1/firewall/cidr adds CIDR rule', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/firewall/cidr',
      payload: { cidr: '10.50.0.0/16', action: 'ALLOW', comment: 'Office subnet' }
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.rule.cidr !== '10.50.0.0/16') {
      throw new Error(`Failed to add CIDR: ${res.body}`);
    }
    createdCidrId = json.rule.id;
  });

  await assert('DELETE /api/v1/firewall/cidr/:id removes CIDR rule', async () => {
    const res = await app.inject({
      method: 'DELETE',
      url: `/api/v1/firewall/cidr/${createdCidrId}`
    });
    const json = JSON.parse(res.body);
    if (!json.success) {
      throw new Error(`Failed to delete CIDR rule: ${res.body}`);
    }
  });

  console.log('\n--- 2. Testing Router & NAT Endpoints ---');

  await assert('GET /api/v1/router/leases returns leases list', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/router/leases' });
    const json = JSON.parse(res.body);
    if (!json.success || !Array.isArray(json.data)) {
      throw new Error(`Invalid leases response: ${res.body}`);
    }
  });

  await assert('GET /api/v1/router/pppoe returns presets', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/router/pppoe' });
    const json = JSON.parse(res.body);
    if (!json.success || json.data.length < 3) {
      throw new Error(`Expected at least 3 ISP presets, got ${json.data?.length}`);
    }
  });

  let createdNatId = 0;
  await assert('POST /api/v1/router/nat adds NAT port forwarding rule', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/router/nat',
      payload: {
        chain: 'dstnat',
        proto: 'tcp',
        inInterface: 'ether1',
        dstPort: '8080',
        toAddress: '192.168.100.50',
        toPort: '80',
        comment: 'Web Port Forward Test'
      }
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.rule.dstPort !== '8080') {
      throw new Error(`Failed to create NAT rule: ${res.body}`);
    }
    createdNatId = json.rule.id;
  });

  await assert('PATCH /api/v1/router/nat toggles rule enabled state', async () => {
    const res = await app.inject({
      method: 'PATCH',
      url: `/api/v1/router/nat/${createdNatId}`,
      payload: { enabled: false }
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.rule.enabled !== false) {
      throw new Error(`Failed to toggle NAT rule: ${res.body}`);
    }
  });

  await assert('DELETE /api/v1/router/nat/:id deletes NAT rule', async () => {
    const res = await app.inject({
      method: 'DELETE',
      url: `/api/v1/router/nat/${createdNatId}`
    });
    const json = JSON.parse(res.body);
    if (!json.success) {
      throw new Error(`Failed to delete NAT rule: ${res.body}`);
    }
  });

  console.log('\n--- 3. Testing DNS & Content Security Endpoints ---');

  await assert('GET /api/v1/dns/services returns 11 categories', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/dns/services' });
    const json = JSON.parse(res.body);
    if (!json.success || json.data.length !== 11) {
      throw new Error(`Expected 11 blocked services, got ${json.data?.length}`);
    }
  });

  await assert('PATCH /api/v1/dns/services toggles service blocked state', async () => {
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/v1/dns/services',
      payload: { id: 'minecraft', blocked: true }
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.service.blocked !== true) {
      throw new Error(`Failed to block service: ${res.body}`);
    }
  });

  let createdRewriteId = '';
  await assert('POST /api/v1/dns/rewrites adds DNS rewrite', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/dns/rewrites',
      payload: { domain: 'portal.aegis.local', answer: '192.168.100.10', type: 'A' }
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.rewrite.domain !== 'portal.aegis.local') {
      throw new Error(`Failed to add DNS rewrite: ${res.body}`);
    }
    createdRewriteId = json.rewrite.id;
  });

  await assert('DELETE /api/v1/dns/rewrites/:id removes DNS rewrite', async () => {
    const res = await app.inject({
      method: 'DELETE',
      url: `/api/v1/dns/rewrites/${createdRewriteId}`
    });
    const json = JSON.parse(res.body);
    if (!json.success) {
      throw new Error(`Failed to delete rewrite: ${res.body}`);
    }
  });

  console.log('\n--- 4. Testing Telemetry & Lockdown Endpoints ---');

  await assert('GET /api/v1/telemetry/live returns telemetry structure', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/telemetry/live' });
    const json = JSON.parse(res.body);
    if (!json.success || typeof json.data.pps !== 'number') {
      throw new Error(`Invalid telemetry payload: ${res.body}`);
    }
  });

  await assert('PATCH /api/v1/telemetry/lockdown toggles emergency lockdown', async () => {
    const res = await app.inject({
      method: 'PATCH',
      url: '/api/v1/telemetry/lockdown',
      payload: { lockdown: true }
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.lockdown !== true) {
      throw new Error(`Failed to set lockdown: ${res.body}`);
    }

    // Reset lockdown to false
    await app.inject({
      method: 'PATCH',
      url: '/api/v1/telemetry/lockdown',
      payload: { lockdown: false }
    });
  });

  await assert('GET /api/v1/telemetry/speedtest/ping returns 200 and pong', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/telemetry/speedtest/ping' });
    const json = JSON.parse(res.body);
    if (res.statusCode !== 200 || !json.pong) {
      throw new Error(`Speedtest ping failed: ${res.body}`);
    }
  });

  await assert('GET /api/v1/telemetry/speedtest/download streams exact binary bytes', async () => {
    const res = await app.inject({
      method: 'GET',
      url: '/api/v1/telemetry/speedtest/download?bytes=131072'
    });
    if (res.statusCode !== 200 || res.rawPayload.length !== 131072) {
      throw new Error(`Expected 131072 bytes, got ${res.rawPayload.length}`);
    }
  });

  await assert('POST /api/v1/telemetry/speedtest/upload counts received bytes correctly', async () => {
    const dummyPayload = Buffer.alloc(65536, 0x55);
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/telemetry/speedtest/upload',
      headers: { 'content-type': 'application/octet-stream' },
      payload: dummyPayload
    });
    const json = JSON.parse(res.body);
    if (!json.success || json.bytesReceived !== 65536) {
      throw new Error(`Speedtest upload failed: ${res.body}`);
    }
  });

  console.log('\n--- 5. Testing Vault & Audit Trail Endpoints ---');

  let backupFilename = '';
  await assert('POST /api/v1/vault/backups creates new snapshot', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/vault/backups',
      payload: { action: 'create' }
    });
    const json = JSON.parse(res.body);
    if (!json.success || !json.backup?.filename) {
      throw new Error(`Failed to create backup: ${res.body}`);
    }
    backupFilename = json.backup.filename;
  });

  await assert('POST /api/v1/vault/restore/:filename restores snapshot', async () => {
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/vault/restore/${backupFilename}`
    });
    const json = JSON.parse(res.body);
    if (!json.success) {
      throw new Error(`Failed to restore backup: ${res.body}`);
    }
  });

  await assert('GET /api/v1/audit/logs returns recorded audit items', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/audit/logs' });
    const json = JSON.parse(res.body);
    if (!json.success || json.data.length === 0) {
      throw new Error(`Expected audit logs to be populated: ${res.body}`);
    }
  });

  console.log('\n--- 6. Testing Cluster Health Endpoint ---');

  await assert('GET /api/v1/cluster/health returns multi-node status', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/cluster/health' });
    const json = JSON.parse(res.body);
    if (!json.success || json.data.overall !== 'HEALTHY' || !json.data.nodes?.kernelFw) {
      throw new Error(`Invalid cluster health response: ${res.body}`);
    }
  });

  console.log('\n--- 7. Testing Path Aliases without /v1 ---');

  await assert('GET /api/firewall/modules works via direct alias', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/firewall/modules' });
    const json = JSON.parse(res.body);
    if (!json.success || json.data.length !== 16) {
      throw new Error(`Alias failed: ${res.body}`);
    }
  });

  await assert('GET /api/cluster/health works via direct alias', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/cluster/health' });
    const json = JSON.parse(res.body);
    if (!json.success || json.data.overall !== 'HEALTHY') {
      throw new Error(`Alias failed: ${res.body}`);
    }
  });

  console.log(`\n========================================`);
  console.log(`Summary: ${passed} Passed, ${failed} Failed`);
  console.log(`========================================`);

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
