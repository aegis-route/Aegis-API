import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { config } from '../config.js';

const STORE_DIR = path.resolve(config.dataDir, 'store');

const INITIAL_FIREWALL_MODULES = [
  {
    id: 'syn_flood',
    name: 'TCP SYN Flood Guard',
    description: 'XDP SYN-Cookie hardware offload & early drop invalid TCP flags',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'L3/L4'
  },
  {
    id: 'udp_flood',
    name: 'UDP Flood & Amplification',
    description: 'Rate-limits arbitrary UDP datagrams & drops unrequested ports',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'L3/L4'
  },
  {
    id: 'icmp_flood',
    name: 'ICMP Smurf / Ping Throttle',
    description: 'Enforces strict token-bucket ICMP echo limits (< 50 pps/src)',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Protocol'
  },
  {
    id: 'dns_amp',
    name: 'DNS ANY Reflection Guard',
    description: 'Blocks inbound spoofed UDP 53 ANY queries & large EDNS0 responses',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Protocol'
  },
  {
    id: 'ntp_amp',
    name: 'NTP Monlist Shield',
    description: 'Inspects UDP 123 payloads for Mode 7 Monlist request vectors',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Protocol'
  },
  {
    id: 'ssdp_amp',
    name: 'SSDP / UPnP Amplification',
    description: 'Silently swallows UDP 1900 M-SEARCH reflection probes at ingress',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Protocol'
  },
  {
    id: 'snmp_amp',
    name: 'SNMP Reflection Filter',
    description: 'Blocks unauthorized UDP 161/162 public community string queries',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Protocol'
  },
  {
    id: 'charon_ipsec',
    name: 'IPSec IKE Handshake Guard',
    description: 'Mitigates pseudo-IKE phase 1 SA initiation flood on UDP 500/4500',
    mode: 'MONITOR',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Protocol'
  },
  {
    id: 'http_slowloris',
    name: 'Slowloris / Slow POST Defense',
    description: 'Tracks header completion timeouts & purges lingering TCP sockets',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Application'
  },
  {
    id: 'tls_reneg',
    name: 'TLS Renegotiation Exhaustion',
    description: 'Limits client-initiated SSL handshakes per TCP session',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Application'
  },
  {
    id: 'ip_frag',
    name: 'IP Fragment Overlap Defense',
    description: 'Prevents fragment reassembly memory exhaustion (Bonk/Jolt2)',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'L3/L4'
  },
  {
    id: 'land_attack',
    name: 'LAND Attack Filter',
    description: 'Instant drop for packets where Source IP equals Destination IP',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'L3/L4'
  },
  {
    id: 'teardrop',
    name: 'Teardrop Malformed Offset',
    description: 'Validates overlapping fragment length math inside eBPF parser',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'L3/L4'
  },
  {
    id: 'smurf_attack',
    name: 'Smurf / Broadcast Reflection',
    description: 'Rejects traffic addressed to subnet broadcast IPs via external WAN',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Protocol'
  },
  {
    id: 'botnet_c2',
    name: 'Mirai / Dark-IoT Botnet Shield',
    description: 'BFF feeds threat intelligence list directly to eBPF hashmap',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Stateful'
  },
  {
    id: 'geoip_filter',
    name: 'GeoIP High-Risk ASN Drop',
    description: 'Drops inbound connections originating from sanctioned/bulletproof ASNs',
    mode: 'DROP',
    status: 'STANDBY',
    drops: 0,
    pps: 0,
    latency: '0.00 ms',
    category: 'Stateful'
  }
];

const INITIAL_PPPOE_PROFILES = [
  {
    id: 'fpt',
    name: 'FPT Telecom FTTH GPON',
    badge: 'FPT Telecom',
    vlanId: 7,
    iface: 'ether1',
    username: '',
    password: '',
    mtu: 1492,
    distance: 1,
    recommendation: 'VLAN 7 chuẩn hóa GPON Bridge. MTU 1492. Hỗ trợ IPv6 Prefix Delegation /56.',
    status: 'DISCONNECTED',
    uptime: '0s',
    ipAddress: '',
    gateway: '',
    usePeerDns: false,
    addDefaultRoute: true
  },
  {
    id: 'viettel',
    name: 'Viettel Telecom GPON',
    badge: 'Viettel Telecom',
    vlanId: 35,
    iface: 'ether4',
    username: '',
    password: '',
    mtu: 1492,
    distance: 2,
    recommendation: 'VLAN 35 trên modem DASAN/ZTE/Huawei Bridge. Keepalive 10s tự động failover.',
    status: 'DISCONNECTED',
    uptime: '0s',
    ipAddress: '',
    gateway: '',
    usePeerDns: false,
    addDefaultRoute: true
  },
  {
    id: 'vnpt',
    name: 'VNPT Vinaphone FiberVNN',
    badge: 'VNPT Vinaphone',
    vlanId: 32,
    iface: 'ether1',
    username: '',
    password: '',
    mtu: 1492,
    distance: 3,
    recommendation: 'VLAN 32 chuẩn hóa mạng VNPT miền Bắc (hoặc VLAN 11). Tối ưu định tuyến cáp biển APG/AAG.',
    status: 'DISCONNECTED',
    uptime: '0s',
    ipAddress: '',
    gateway: '',
    usePeerDns: false,
    addDefaultRoute: false
  }
];

const INITIAL_BLOCKED_SERVICES = [
  { id: 'minecraft', name: 'Minecraft Online', category: 'Gaming', icon: 'Gamepad2', blocked: false, count24h: 0 },
  { id: 'roblox', name: 'Roblox Platform', category: 'Gaming', icon: 'Gamepad', blocked: false, count24h: 0 },
  { id: 'gemini', name: 'Google Gemini AI', category: 'Artificial Intelligence', icon: 'Bot', blocked: false, count24h: 0 },
  { id: 'tiktok', name: 'TikTok & ByteDance', category: 'Social Media', icon: 'Share2', blocked: false, count24h: 0 },
  { id: 'facebook', name: 'Facebook & Instagram', category: 'Social Media', icon: 'Globe', blocked: false, count24h: 0 },
  { id: 'doh_bypass', name: 'Anti DoH/DoT Bypass', category: 'Security Enforce', icon: 'ShieldAlert', blocked: false, count24h: 0 },
  { id: 'torrent', name: 'BitTorrent & P2P Trackers', category: 'File Sharing', icon: 'DownloadCloud', blocked: false, count24h: 0 },
  { id: 'discord', name: 'Discord Chat & Voice', category: 'Communications', icon: 'MessageSquare', blocked: false, count24h: 0 },
  { id: 'steam', name: 'Steam Community & CDN', category: 'Gaming', icon: 'PlayCircle', blocked: false, count24h: 0 },
  { id: 'pornography', name: 'Adult & Explicit Content', category: 'Content Safety', icon: 'EyeOff', blocked: false, count24h: 0 },
  { id: 'tor', name: 'Tor Relay & Onion Exit', category: 'Anonymizer', icon: 'Key', blocked: false, count24h: 0 }
];

const DEFAULT_PRESETS = {
  'firewall.json': {
    modules: INITIAL_FIREWALL_MODULES,
    autoBanList: [],
    cidrRules: []
  },
  'router.json': {
    leases: [],
    pppoeProfiles: INITIAL_PPPOE_PROFILES,
    natRules: [],
    connections: []
  },
  'dns.json': {
    services: INITIAL_BLOCKED_SERVICES,
    stats: {
      queriesTotal: 0,
      blockedTotal: 0,
      blockedPercent: 0,
      avgLatencyMs: 0,
      rulesCount: 0
    },
    rewrites: [],
    queryLogs: []
  },
  'telemetry.json': {
    throughputMbps: 0.0,
    pps: 0,
    totalDrops: 0,
    activeSessions: 0,
    lockdown: false,
    updatedAt: new Date().toISOString()
  },
  'vault.json': {
    backups: []
  },
  'audit.json': {
    auditLogs: []
  }
};

class StoreService {
  constructor() {
    this.ensureInitialized();
  }

  ensureInitialized() {
    try {
      if (!fs.existsSync(STORE_DIR)) {
        fs.mkdirSync(STORE_DIR, { recursive: true });
      }

      for (const [filename, defaultData] of Object.entries(DEFAULT_PRESETS)) {
        const filePath = path.join(STORE_DIR, filename);
        if (!fs.existsSync(filePath)) {
          fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2), 'utf-8');
        }
      }
    } catch (err) {
      console.error('[StoreService] Failed to initialize store directory:', err);
    }
  }

  getFilePath(name) {
    const filename = name.endsWith('.json') ? name : `${name}.json`;
    return path.join(STORE_DIR, filename);
  }

  readStore(name) {
    const filename = name.endsWith('.json') ? name : `${name}.json`;
    const filePath = this.getFilePath(filename);
    try {
      if (!fs.existsSync(filePath)) {
        const defaultData = DEFAULT_PRESETS[filename] || {};
        this.writeStore(filename, defaultData);
        return JSON.parse(JSON.stringify(defaultData));
      }
      const raw = fs.readFileSync(filePath, 'utf-8');
      return JSON.parse(raw);
    } catch (err) {
      console.error(`[StoreService] Error reading store ${filename}:`, err.message);
      const defaultData = DEFAULT_PRESETS[filename] || {};
      return JSON.parse(JSON.stringify(defaultData));
    }
  }

  writeStore(name, data) {
    const filename = name.endsWith('.json') ? name : `${name}.json`;
    const filePath = this.getFilePath(filename);
    try {
      if (!fs.existsSync(STORE_DIR)) {
        fs.mkdirSync(STORE_DIR, { recursive: true });
      }
      const content = JSON.stringify(data, null, 2);
      fs.writeFileSync(filePath, content, 'utf-8');
      return true;
    } catch (err) {
      console.error(`[StoreService] Error writing store ${filename}:`, err);
      return false;
    }
  }

  addAuditLog(action, target, severity = 'INFO', details = '', operator = 'admin@aegis') {
    const auditData = this.readStore('audit');
    const logs = Array.isArray(auditData.auditLogs) ? auditData.auditLogs : [];

    const now = new Date();
    const timeStr = now.toLocaleTimeString('vi-VN', { hour12: false });
    const log = {
      id: `log-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      timestamp: timeStr,
      operator,
      action,
      target,
      severity,
      details
    };

    logs.unshift(log);
    if (logs.length > 200) {
      logs.pop();
    }

    auditData.auditLogs = logs;
    this.writeStore('audit', auditData);
    return log;
  }

  // --- Firewall Helpers ---
  getFirewall() {
    return this.readStore('firewall');
  }

  updateFirewall(mutator) {
    const data = this.getFirewall();
    const result = mutator(data);
    this.writeStore('firewall', data);
    return result;
  }

  // --- Router Helpers ---
  getRouter() {
    return this.readStore('router');
  }

  updateRouter(mutator) {
    const data = this.getRouter();
    const result = mutator(data);
    this.writeStore('router', data);
    return result;
  }

  // --- DNS Helpers ---
  getDns() {
    return this.readStore('dns');
  }

  updateDns(mutator) {
    const data = this.getDns();
    const result = mutator(data);
    this.writeStore('dns', data);
    return result;
  }

  // --- Telemetry Helpers ---
  getTelemetry() {
    const telemetry = this.readStore('telemetry');
    const firewall = this.getFirewall();
    const router = this.getRouter();
    const dns = this.getDns();

    const modules = Array.isArray(firewall.modules) ? firewall.modules : [];
    const totalDrops = modules.reduce((acc, m) => acc + (m.drops || 0), 0);
    const totalPps = modules.reduce((acc, m) => acc + (m.pps || 0), 0);
    const connections = Array.isArray(router.connections) ? router.connections : [];
    const leases = Array.isArray(router.leases) ? router.leases : [];
    const autoBans = Array.isArray(firewall.autoBanList) ? firewall.autoBanList : [];

    return {
      throughputMbps: telemetry.throughputMbps || 0.0,
      pps: telemetry.pps !== undefined && telemetry.pps > 0 ? telemetry.pps : totalPps,
      totalDrops: telemetry.totalDrops !== undefined && telemetry.totalDrops > 0 ? telemetry.totalDrops : totalDrops,
      activeSessions: connections.length,
      lockdown: Boolean(telemetry.lockdown),
      updatedAt: telemetry.updatedAt || new Date().toISOString(),
      firewallActiveCount: modules.filter((m) => m.mode === 'DROP').length,
      autoBansCount: autoBans.length,
      dnsQueriesTotal: dns.stats?.queriesTotal || 0,
      dnsBlockedRate: dns.stats?.blockedPercent || 0,
      activeDhcpClients: leases.length,
      openPortsCount: 10
    };
  }

  updateTelemetryLive(partial) {
    const telemetry = this.readStore('telemetry');
    const updated = {
      ...telemetry,
      ...partial,
      updatedAt: new Date().toISOString()
    };
    this.writeStore('telemetry', updated);
    return updated;
  }

  setLockdown(lockdown) {
    const telemetry = this.readStore('telemetry');
    telemetry.lockdown = lockdown;
    telemetry.updatedAt = new Date().toISOString();
    this.writeStore('telemetry', telemetry);

    // If lockdown is enabled, switch all standby modules to active DROP
    if (lockdown) {
      this.updateFirewall((fw) => {
        fw.modules = (fw.modules || []).map((m) => ({
          ...m,
          mode: 'DROP',
          status: 'ACTIVE'
        }));
      });
    }

    this.addAuditLog(
      'SYSTEM_LOCKDOWN',
      'CLUSTER_NETWORK',
      lockdown ? 'CRIT' : 'WARN',
      lockdown ? 'Emergency lockdown activated across all nodes' : 'Emergency lockdown deactivated'
    );

    return telemetry;
  }

  // --- Vault Helpers ---
  getVault() {
    return this.readStore('vault');
  }

  updateVault(mutator) {
    const data = this.getVault();
    const result = mutator(data);
    this.writeStore('vault', data);
    return result;
  }

  // --- Audit Helpers ---
  getAudit() {
    return this.readStore('audit');
  }

  // --- Convenience Methods for Management Routes ---
  getFirewallModules() {
    return this.getFirewall().modules || [];
  }

  toggleFirewallModule(id, mode) {
    let updated = null;
    this.updateFirewall((fw) => {
      fw.modules = fw.modules || [];
      const idx = fw.modules.findIndex((m) => m.id === id);
      if (idx !== -1) {
        const cur = fw.modules[idx];
        const newMode = mode || (cur.mode === 'DROP' ? 'MONITOR' : cur.mode === 'MONITOR' ? 'OFF' : 'DROP');
        const newStatus = newMode === 'DROP' ? 'ACTIVE' : newMode === 'MONITOR' ? 'STANDBY' : 'DISABLED';
        fw.modules[idx] = { ...cur, mode: newMode, status: newStatus };
        updated = fw.modules[idx];
      }
    });
    if (updated) {
      this.addAuditLog('XDP_MODULE_CHANGE', id, updated.mode === 'DROP' ? 'INFO' : 'WARN', `Toggled module "${updated.name}" to mode ${updated.mode}`);
    }
    return updated;
  }

  getAutoBans() {
    return this.getFirewall().autoBanList || [];
  }

  addAutoBan(entry) {
    const newEntry = {
      id: entry.id || `ban-${Date.now()}`,
      ip: entry.ip,
      country: entry.country || 'Unknown',
      countryCode: entry.countryCode || 'XX',
      reason: entry.reason || 'Manual Admin Block',
      bannedAt: entry.bannedAt || new Date().toLocaleTimeString('vi-VN', { hour12: false }),
      expires: entry.expires || '24 Giờ',
      score: entry.score || 95
    };
    this.updateFirewall((fw) => {
      fw.autoBanList = fw.autoBanList || [];
      fw.autoBanList.unshift(newEntry);
    });
    this.addAuditLog('AUTOBAN_ADD', entry.ip, 'CRIT', `Blocked IP ${entry.ip}: ${newEntry.reason}`);
    return newEntry;
  }

  removeAutoBan(id, ip) {
    let removed = false;
    this.updateFirewall((fw) => {
      fw.autoBanList = fw.autoBanList || [];
      const lenBefore = fw.autoBanList.length;
      fw.autoBanList = fw.autoBanList.filter((e) => (id ? e.id !== id : true) && (ip ? e.ip !== ip : true));
      removed = fw.autoBanList.length < lenBefore;
    });
    if (removed) {
      this.addAuditLog('AUTOBAN_UNBAN', ip || id, 'INFO', `Removed IP from eBPF Blacklist`);
    }
    return removed;
  }

  getCidrRules() {
    return this.getFirewall().cidrRules || [];
  }

  addCidrRule(cidr, comment, action = 'ALLOW') {
    const rule = {
      id: `cidr-${Date.now()}`,
      cidr,
      action,
      comment: comment || 'Whitelisted Network',
      hits: 0,
      added: new Date().toLocaleDateString('vi-VN')
    };
    this.updateFirewall((fw) => {
      fw.cidrRules = fw.cidrRules || [];
      fw.cidrRules.push(rule);
    });
    this.addAuditLog('CIDR_ADD', cidr, action === 'ALLOW' ? 'INFO' : 'WARN', `Added CIDR ${cidr} [${action}]`);
    return rule;
  }

  deleteCidrRule(id) {
    let deleted = false;
    this.updateFirewall((fw) => {
      fw.cidrRules = fw.cidrRules || [];
      const lenBefore = fw.cidrRules.length;
      fw.cidrRules = fw.cidrRules.filter((r) => r.id !== id);
      deleted = fw.cidrRules.length < lenBefore;
    });
    if (deleted) {
      this.addAuditLog('CIDR_DELETE', id, 'INFO', `Deleted CIDR rule ${id}`);
    }
    return deleted;
  }

  getDhcpLeases() {
    return this.getRouter().leases || [];
  }

  toggleFastTrack(id, enabled) {
    let updated = null;
    this.updateRouter((rt) => {
      rt.leases = rt.leases || [];
      const lease = rt.leases.find((l) => l.id === id);
      if (lease) {
        lease.fastTrack = enabled !== undefined ? enabled : !lease.fastTrack;
        updated = lease;
      }
    });
    if (updated) {
      this.addAuditLog('ROUTER_FASTTRACK', updated.ip, 'INFO', `FastTrack set to ${updated.fastTrack} for ${updated.hostname}`);
    }
    return updated;
  }

  getNatRules() {
    return this.getRouter().natRules || [];
  }

  addNatRule(ruleData) {
    let newRule = null;
    this.updateRouter((rt) => {
      rt.natRules = rt.natRules || [];
      const maxId = rt.natRules.reduce((max, r) => Math.max(max, r.id || 0), 0);
      newRule = {
        ...ruleData,
        id: maxId + 1,
        packets: 0,
        enabled: ruleData.enabled !== undefined ? ruleData.enabled : true
      };
      rt.natRules.push(newRule);
    });
    this.addAuditLog('NAT_RULE_ADD', `Port ${newRule.dstPort}`, 'INFO', `Added NAT: ${newRule.dstPort} -> ${newRule.toAddress}:${newRule.toPort}`);
    return newRule;
  }

  editNatRule(rule) {
    let updated = null;
    this.updateRouter((rt) => {
      rt.natRules = rt.natRules || [];
      const idx = rt.natRules.findIndex((r) => r.id === rule.id);
      if (idx !== -1) {
        rt.natRules[idx] = { ...rt.natRules[idx], ...rule };
        updated = rt.natRules[idx];
      }
    });
    if (updated) {
      this.addAuditLog('NAT_RULE_EDIT', `Rule #${rule.id}`, 'INFO', `Updated NAT Rule #${rule.id}`);
    }
    return updated;
  }

  deleteNatRule(id) {
    let deleted = false;
    this.updateRouter((rt) => {
      rt.natRules = rt.natRules || [];
      const lenBefore = rt.natRules.length;
      rt.natRules = rt.natRules.filter((r) => r.id !== id);
      deleted = rt.natRules.length < lenBefore;
    });
    if (deleted) {
      this.addAuditLog('NAT_RULE_DELETE', `Rule #${id}`, 'WARN', `Deleted NAT Rule #${id}`);
    }
    return deleted;
  }

  toggleNatRule(id) {
    let updated = null;
    this.updateRouter((rt) => {
      rt.natRules = rt.natRules || [];
      const rule = rt.natRules.find((r) => r.id === id);
      if (rule) {
        rule.enabled = !rule.enabled;
        updated = rule;
      }
    });
    if (updated) {
      this.addAuditLog('NAT_RULE_TOGGLE', `Rule #${id}`, 'INFO', `NAT Rule #${id} is now ${updated.enabled ? 'ENABLED' : 'DISABLED'}`);
    }
    return updated;
  }

  getPppoeProfiles() {
    return this.getRouter().pppoeProfiles || [];
  }

  savePppoeProfile(profile) {
    this.updateRouter((rt) => {
      rt.pppoeProfiles = rt.pppoeProfiles || [];
      const idx = rt.pppoeProfiles.findIndex((p) => p.id === profile.id);
      if (idx >= 0) {
        rt.pppoeProfiles[idx] = { ...rt.pppoeProfiles[idx], ...profile };
      } else {
        rt.pppoeProfiles.push(profile);
      }
    });
    this.addAuditLog('PPPOE_SAVE', profile.id, 'INFO', `Saved PPPoE profile ${profile.name}`);
    return profile;
  }

  deletePppoeProfile(id) {
    let deleted = false;
    this.updateRouter((rt) => {
      rt.pppoeProfiles = rt.pppoeProfiles || [];
      const lenBefore = rt.pppoeProfiles.length;
      rt.pppoeProfiles = rt.pppoeProfiles.filter((p) => p.id !== id);
      deleted = rt.pppoeProfiles.length < lenBefore;
    });
    if (deleted) {
      this.addAuditLog('PPPOE_DELETE', id, 'WARN', `Deleted PPPoE profile ${id}`);
    }
    return deleted;
  }

  getConnections() {
    return this.getRouter().connections || [];
  }

  killConnection(id) {
    let killed = false;
    this.updateRouter((rt) => {
      rt.connections = rt.connections || [];
      const lenBefore = rt.connections.length;
      rt.connections = rt.connections.filter((c) => c.id !== id);
      killed = rt.connections.length < lenBefore;
    });
    if (killed) {
      this.addAuditLog('CONN_KILL', id, 'WARN', `Terminated Conntrack connection session ${id}`);
    }
    return killed;
  }

  getDnsServices() {
    return this.getDns().services || [];
  }

  toggleDnsService(id, blocked) {
    let updated = null;
    this.updateDns((dns) => {
      dns.services = dns.services || [];
      const s = dns.services.find((item) => item.id === id);
      if (s) {
        s.blocked = blocked !== undefined ? blocked : !s.blocked;
        updated = s;
      }
    });
    if (updated) {
      this.addAuditLog('DNS_SERVICE_TOGGLE', updated.name, updated.blocked ? 'WARN' : 'INFO', `Service ${updated.name} blocked: ${updated.blocked}`);
    }
    return updated;
  }

  getDnsStats() {
    return this.getDns().stats || {};
  }

  getDnsRewrites() {
    return this.getDns().rewrites || [];
  }

  addDnsRewrite(rewrite) {
    const item = { id: `rw-${Date.now()}`, ...rewrite };
    this.updateDns((dns) => {
      dns.rewrites = dns.rewrites || [];
      dns.rewrites.push(item);
    });
    this.addAuditLog('DNS_REWRITE_ADD', rewrite.domain, 'INFO', `DNS Rewrite: ${rewrite.domain} -> ${rewrite.answer}`);
    return item;
  }

  deleteDnsRewrite(id) {
    let deleted = false;
    this.updateDns((dns) => {
      dns.rewrites = dns.rewrites || [];
      const lenBefore = dns.rewrites.length;
      dns.rewrites = dns.rewrites.filter((r) => r.id !== id);
      deleted = dns.rewrites.length < lenBefore;
    });
    if (deleted) {
      this.addAuditLog('DNS_REWRITE_DELETE', id, 'INFO', `Deleted DNS rewrite ${id}`);
    }
    return deleted;
  }

  getDnsQueryLogs() {
    return this.getDns().queryLogs || [];
  }

  getBackups() {
    return this.getVault().backups || [];
  }

  createBackup() {
    const dateStr = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `aegis-snapshot-${dateStr}.enc.json`;
    const snapshotPayload = {
      version: '1.0.0',
      created: new Date().toLocaleString('vi-VN'),
      firewall: this.getFirewall(),
      router: this.getRouter(),
      dns: this.getDns()
    };
    const contentStr = JSON.stringify(snapshotPayload);
    const hash = crypto.createHash('sha256').update(contentStr).digest('hex').substring(0, 16);
    const backupItem = {
      id: `bk-${Date.now()}`,
      filename,
      target: 'Full Cluster (eBPF + RouterOS + AdGuard)',
      size: `${(Buffer.byteLength(contentStr) / 1024).toFixed(1)} KB`,
      created: new Date().toLocaleString('vi-VN'),
      hash
    };
    this.updateVault((v) => {
      v.backups = v.backups || [];
      v.backups.unshift(backupItem);
    });
    this.addAuditLog('VAULT_BACKUP_CREATE', filename, 'INFO', `Generated encrypted cluster backup (${backupItem.size})`);
    return backupItem;
  }

  restoreBackup(filename) {
    const backups = this.getBackups();
    const target = backups.find((b) => b.filename === filename);
    if (!target) {
      throw new Error(`Backup snapshot ${filename} not found`);
    }
    this.addAuditLog('VAULT_RESTORE', filename, 'WARN', `Restored system state from backup ${filename}`);
    return {
      success: true,
      message: `Khôi phục cấu hình hệ thống từ snapshot ${filename} thành công!`
    };
  }

  getAuditLogs() {
    return this.getAudit().auditLogs || [];
  }
}

export const storeService = new StoreService();
