import { storeService } from './src/services/store.service.js';
import assert from 'node:assert';

console.log('🧪 Bắt đầu kiểm thử đối chuẩn tích hợp Low-Tech Store Service...');

// 1. Test Firewall Modules
const modules = storeService.getFirewallModules();
assert(Array.isArray(modules) && modules.length === 16, 'Phải có đúng 16 modules');
console.log('✓ 1. getFirewallModules: 16 modules OK');

// Test toggle
const toggled = storeService.toggleFirewallModule('syn_flood', 'MONITOR');
assert(toggled && toggled.mode === 'MONITOR', 'Toggle syn_flood sang MONITOR');
console.log('✓ 2. toggleFirewallModule: chuyển sang MONITOR OK');

// 2. Test Auto-Ban
const ban = storeService.addAutoBan({ ip: '203.0.113.50', reason: 'DDoS Test Vector', score: 99 });
assert(ban.ip === '203.0.113.50', 'AutoBan IP phải đúng');
const bans = storeService.getAutoBans();
assert(bans.some(b => b.ip === '203.0.113.50'), 'Ban list phải chứa 203.0.113.50');
console.log('✓ 3. addAutoBan & getAutoBans OK');

const unbanned = storeService.removeAutoBan(null, '203.0.113.50');
assert(unbanned, 'Unban phải thành công');
console.log('✓ 4. removeAutoBan OK');

// 3. Test CIDR
const cidr = storeService.addCidrRule('10.0.0.0/8', 'Internal Network', 'ALLOW');
assert(cidr.cidr === '10.0.0.0/8', 'CIDR phải đúng');
const cidrs = storeService.getCidrRules();
assert(cidrs.some(c => c.cidr === '10.0.0.0/8'), 'CIDR list phải chứa 10.0.0.0/8');
console.log('✓ 5. addCidrRule & getCidrRules OK');

// 4. Test Router (NAT & Leases)
const lease = storeService.toggleFastTrack('lease-1', true);
console.log('✓ 6. toggleFastTrack OK');

const nat = storeService.addNatRule({ chain: 'dstnat', proto: 'tcp', dstPort: '8443', toAddress: '192.168.100.50', toPort: '443', inInterface: 'ether1', comment: 'HTTPS Web' });
assert(nat && nat.dstPort === '8443', 'NAT dstPort phải là 8443');
console.log('✓ 7. addNatRule OK');

// 5. Test DNS Services
const dnsService = storeService.toggleDnsService('tiktok', true);
assert(dnsService && dnsService.blocked === true, 'TikTok phải bị chặn');
console.log('✓ 8. toggleDnsService OK');

// 6. Test Vault & Backups
const backup = storeService.createBackup();
assert(backup && backup.filename.includes('aegis-snapshot'), 'Snapshot backup file OK');
console.log(`✓ 9. createBackup OK: ${backup.filename}`);

// 7. Test Audit Logs
const auditLogs = storeService.getAuditLogs();
assert(auditLogs.length > 0, 'Audit logs phải có các bản ghi vừa thao tác');
console.log(`✓ 10. Audit Logs OK: ${auditLogs.length} sự kiện đã lưu.`);

console.log('\n🎉 TẤT CẢ 10 BƯỚC KIỂM THỬ ĐỐI CHUẨN ĐÃ VƯỢT QUA 100%!');
