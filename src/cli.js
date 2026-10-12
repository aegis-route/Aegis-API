#!/usr/bin/env node

import readline from 'node:readline';
import process from 'node:process';
import { config } from './config.js';
import { geoService } from './services/geo.service.js';
import { formatService } from './services/format.service.js';
import { threatService } from './services/threat.service.js';
import { syncService } from './services/sync.service.js';

// ANSI Color Helpers
const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  italic: '\x1b[3m',
  underline: '\x1b[4m',

  // Foreground
  black: '\x1b[30m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m',

  // Bright
  brightRed: '\x1b[91m',
  brightGreen: '\x1b[92m',
  brightYellow: '\x1b[93m',
  brightBlue: '\x1b[94m',
  brightMagenta: '\x1b[95m',
  brightCyan: '\x1b[96m',
  brightWhite: '\x1b[97m',

  // Background
  bgBlue: '\x1b[44m',
  bgMagenta: '\x1b[45m',
  bgCyan: '\x1b[46m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m'
};

const COMMANDS = [
  'help',
  'lookup',
  'info',
  'threat',
  'raw',
  'asn',
  'city',
  'country',
  'status',
  'sync',
  'keys',
  'clear',
  'exit',
  'quit'
];

/**
 * Print stylized banner
 */
function printBanner() {
  console.log(`
${C.bold}${C.brightCyan}╔══════════════════════════════════════════════════════════════════════╗
║   ${C.brightMagenta}🛡️   AEGIS IP INTELLIGENCE CLI AGENT${C.brightCyan}                               ║
║   ${C.gray}MaxMind MMDB • Threat Multi-Engine • Realtime WHOIS/RDAP${C.brightCyan}           ║
╚══════════════════════════════════════════════════════════════════════╝${C.reset}`);
}

/**
 * Print help menu
 */
function printHelp() {
  console.log(`
${C.bold}${C.brightYellow}COMMANDS & USAGE:${C.reset}
  ${C.bold}${C.brightCyan}<ip>${C.reset}                  Tra cứu phân tích toàn diện IP (ví dụ: ${C.italic}1.1.1.1${C.reset} hoặc ${C.italic}8.8.8.8${C.reset})
  ${C.bold}${C.brightCyan}lookup <ip>${C.reset}           Tra cứu đầy đủ thông tin IP (hoặc ${C.brightCyan}info <ip>${C.reset})
  ${C.bold}${C.brightCyan}threat <ip>${C.reset}           Kiểm tra chuyên sâu bảo mật (VPN, Proxy, Tor, Relay, Hosting)
  ${C.bold}${C.brightCyan}raw <ip>${C.reset}              Hiển thị JSON schema IPInfo Enterprise chuẩn forms.txt
  ${C.bold}${C.brightCyan}asn <ip>${C.reset}              Tra cứu thông tin ASN nội bộ từ MMDB
  ${C.bold}${C.brightCyan}city <ip>${C.reset}             Tra cứu thông tin City / Geo nội bộ từ MMDB
  ${C.bold}${C.brightCyan}status${C.reset}                Kiểm tra trạng thái databases MMDB, Cron schedule, RAM
  ${C.bold}${C.brightCyan}sync [--force]${C.reset}        Đồng bộ cập nhật cơ sở dữ liệu GeoLite2 mới nhất
  ${C.bold}${C.brightCyan}keys${C.reset}                  Kiểm tra trạng thái các API key đã nạp từ .env
  ${C.bold}${C.brightCyan}clear${C.reset}                 Xóa màn hình terminal
  ${C.bold}${C.brightCyan}exit${C.reset} / ${C.bold}${C.brightCyan}quit${C.reset}             Thoát khỏi Aegis CLI
`);
}

/**
 * Format badge tag
 */
function badge(text, isPositive, positiveColor = C.brightRed, negativeColor = C.green) {
  if (isPositive) {
    return `${positiveColor}${C.bold}[ ${text} ]${C.reset}`;
  }
  return `${negativeColor}[ NO ]${C.reset}`;
}

/**
 * Display formatted IP intelligence report
 */
async function handleLookup(ip, raw = false) {
  if (!geoService.isValidIp(ip)) {
    console.log(`${C.brightRed}✖ Lỗi:${C.reset} Địa chỉ IP '${ip}' không hợp lệ (hỗ trợ IPv4 và IPv6).`);
    return;
  }

  process.stdout.write(`${C.gray}⏳ Đang phân tích IP ${ip}...${C.reset}\r`);
  const startTime = Date.now();

  try {
    const data = await formatService.format(ip, { enrich: true });
    const duration = Date.now() - startTime;
    process.stdout.write(' '.repeat(40) + '\r');

    if (raw) {
      console.log(JSON.stringify(data, null, 2));
      return;
    }

    console.log(`\n${C.bold}${C.bgBlue}${C.brightWhite} IP INTELLIGENCE REPORT: ${ip} ${C.reset} ${C.gray}(${duration}ms)${C.reset}\n`);

    // 1. General Info
    console.log(`${C.bold}${C.brightCyan}┌─ 🌐 TỔNG QUAN HỆ THỐNG${C.reset}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}IP Address:${C.reset}      ${C.brightWhite}${data.ip}${C.reset}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Reverse DNS:${C.reset}     ${data.hostname ? C.brightGreen + data.hostname : C.gray + 'Không có PTR record'}${C.reset}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}ASN Network:${C.reset}     ${C.brightYellow}${data.as.asn || 'N/A'}${C.reset} - ${C.bold}${data.as.name || 'N/A'}${C.reset}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}ASN Type/Domain:${C.reset} ${data.as.type || 'N/A'} ${data.as.domain ? `(${data.as.domain})` : ''}`);

    // 2. Geolocation
    const geo = data.geo || {};
    console.log(`${C.brightCyan}├─ 📍 VỊ TRÍ ĐỊA LÝ (GEOLOCATION)${C.reset}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Quốc gia:${C.reset}        ${geo.country || 'N/A'} (${geo.country_code || 'N/A'}) - Châu lục: ${geo.continent || 'N/A'}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Thành phố / Bang:${C.reset} ${geo.city || 'N/A'}${geo.region ? ', ' + geo.region : ''}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Tọa độ / Múi giờ:${C.reset} Lat: ${geo.latitude || 'N/A'}, Lon: ${geo.longitude || 'N/A'} | ${geo.timezone || 'N/A'}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Mã bưu chính:${C.reset}    ${geo.postal_code || 'N/A'} (Bán kính tin cậy: ${geo.radius || 'N/A'} km)`);

    // 3. Security & Threat
    const anon = data.anonymous || {};
    console.log(`${C.brightCyan}├─ 🛡️  BẢO MẬT & PHÁT HIỆN THREAT${C.reset}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}VPN:${C.reset}             ${badge('VPN DETECTED', anon.is_vpn)}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Proxy:${C.reset}           ${badge('PROXY DETECTED', anon.is_proxy)}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Tor Node:${C.reset}        ${badge('TOR EXIT NODE', anon.is_tor)}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Relay / Apple:${C.reset}   ${badge('RELAY DETECTED', anon.is_relay)}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Res-Proxy:${C.reset}       ${badge('RESIDENTIAL PROXY', anon.is_res_proxy)}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Datacenter/Host:${C.reset} ${badge('HOSTING / DATACENTER', data.is_hosting, C.yellow)}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Anycast / BGP:${C.reset}   ${badge('ANYCAST NETWORK', data.is_anycast, C.cyan)}`);

    // 4. Company & Abuse
    const company = data.company || {};
    const abuse = data.abuse || {};
    console.log(`${C.brightCyan}├─ 🏢 TỔ CHỨC & LIÊN HỆ ABUSE${C.reset}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Company:${C.reset}         ${company.name || 'N/A'} (${company.domain || 'N/A'})`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Abuse Name:${C.reset}      ${abuse.name || 'N/A'}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Abuse Email:${C.reset}     ${abuse.email ? C.brightCyan + abuse.email + C.reset : 'N/A'}`);
    console.log(`${C.brightCyan}│${C.reset}  ${C.bold}Abuse Network:${C.reset}   ${abuse.network || 'N/A'}`);

    // 5. Hosted Domains
    const dom = data.domains || {};
    console.log(`${C.brightCyan}└─ 🔗 HOSTED DOMAINS (PASSIVE DNS)${C.reset}`);
    console.log(`   ${C.bold}Tổng số domain:${C.reset}  ${dom.total || 0}`);
    if (dom.domains && dom.domains.length > 0) {
      console.log(`   ${C.bold}Mẫu domains:${C.reset}     ${dom.domains.map(d => C.brightGreen + d + C.reset).join(', ')}`);
    } else {
      console.log(`   ${C.gray}Không phát hiện domain nào trỏ vào IP này.${C.reset}`);
    }
    console.log('');
  } catch (err) {
    console.log(`\n${C.brightRed}✖ Lỗi khi tra cứu IP:${C.reset} ${err.message}\n`);
  }
}

/**
 * Handle dedicated threat inspection
 */
async function handleThreat(ip) {
  if (!geoService.isValidIp(ip)) {
    console.log(`${C.brightRed}✖ Lỗi:${C.reset} Địa chỉ IP '${ip}' không hợp lệ.`);
    return;
  }

  process.stdout.write(`${C.gray}⏳ Đang kiểm tra Threat engines cho ${ip}...${C.reset}\r`);
  const start = Date.now();
  const threat = await threatService.checkThreat(ip);
  const duration = Date.now() - start;
  process.stdout.write(' '.repeat(40) + '\r');

  console.log(`\n${C.bold}${C.bgRed}${C.brightWhite} THREAT & FRAUD INSPECTION: ${ip} ${C.reset} ${C.gray}(${duration}ms)${C.reset}\n`);
  console.log(`  VPN:               ${badge('VPN', threat.is_vpn)}`);
  console.log(`  Proxy:             ${badge('PROXY', threat.is_proxy)}`);
  console.log(`  Tor Exit Node:     ${badge('TOR', threat.is_tor)}`);
  console.log(`  Relay:             ${badge('RELAY', threat.is_relay)}`);
  console.log(`  Residential Proxy: ${badge('RES-PROXY', threat.is_res_proxy)}`);
  console.log(`  Hosting/Cloud:     ${badge('HOSTING', threat.is_hosting, C.yellow)}`);
  console.log(`  Is Anonymous:      ${threat.is_anonymous ? C.brightRed + C.bold + 'TRUE (RISKY)' : C.brightGreen + 'FALSE (CLEAN)'}${C.reset}\n`);
}

/**
 * Handle system status
 */
async function handleStatus() {
  const geoStatus = geoService.getStatus();
  const syncStatus = await syncService.getStatus();
  const mem = process.memoryUsage();

  console.log(`\n${C.bold}${C.brightCyan}╔═══ SYSTEM & DATABASE STATUS ═══╗${C.reset}`);
  console.log(`${C.bold}Uptime:${C.reset}          ${(process.uptime() / 60).toFixed(1)} phút`);
  console.log(`${C.bold}RAM Heap Used:${C.reset}   ${(mem.heapUsed / 1024 / 1024).toFixed(2)} MB / ${(mem.heapTotal / 1024 / 1024).toFixed(2)} MB`);
  console.log(`${C.bold}Cron Schedule:${C.reset}   '${syncStatus.cronSchedule}' (Hourly check)`);
  console.log(`${C.bold}Upstream Tag:${C.reset}    ${syncStatus.currentReleaseTag || 'Chưa sync'}`);
  console.log(`${C.bold}Last Sync Time:${C.reset}  ${syncStatus.lastSyncTime || 'N/A'}\n`);

  console.log(`${C.bold}${C.brightYellow}In-Memory Databases:${C.reset}`);
  for (const [type, info] of Object.entries(geoStatus)) {
    const sizeMb = (info.size / 1024 / 1024).toFixed(2);
    const statusIcon = info.loaded ? `${C.brightGreen}✓ LOADED${C.reset}` : `${C.brightRed}✖ NOT LOADED${C.reset}`;
    console.log(`  • ${C.bold}${type.toUpperCase().padEnd(8)}${C.reset} : ${statusIcon} [${info.file}] (${sizeMb} MB)`);
  }
  console.log('');
}

/**
 * Handle sync trigger
 */
async function handleSync(force = false) {
  console.log(`${C.brightYellow}🔄 Bắt đầu kiểm tra & đồng bộ GeoLite2 MMDB (force=${force})...${C.reset}`);
  try {
    const res = await syncService.sync(force);
    if (res.updated) {
      console.log(`${C.brightGreen}✓ Hoàn tất! Cơ sở dữ liệu đã được cập nhật sang release ${res.releaseTag}.${C.reset}`);
    } else {
      console.log(`${C.brightGreen}✓ Cơ sở dữ liệu đã ở bản mới nhất (${res.releaseTag}). Không cần tải lại.${C.reset}`);
    }
  } catch (err) {
    console.log(`${C.brightRed}✖ Lỗi đồng bộ:${C.reset} ${err.message}`);
  }
  console.log('');
}

/**
 * Handle listing configured keys
 */
function handleKeys() {
  console.log(`\n${C.bold}${C.brightYellow}CONFIGURED API KEYS IN .ENV:${C.reset}`);
  const keys = config.keys;
  let count = 0;
  for (const [name, val] of Object.entries(keys)) {
    const isSet = Boolean(val && val.trim().length > 0);
    if (isSet) count++;
    const status = isSet 
      ? `${C.brightGreen}✓ CONFIGURED${C.reset} ${C.gray}(${val.slice(0, 4)}...${val.slice(-4)})${C.reset}`
      : `${C.gray}○ NOT SET${C.reset}`;
    console.log(`  • ${name.padEnd(18)}: ${status}`);
  }
  console.log(`\n${C.bold}Tổng số key đang hoạt động:${C.reset} ${count} / ${Object.keys(keys).length}\n`);
}

/**
 * Tab completer for readline
 */
function completer(line) {
  const hits = COMMANDS.filter((c) => c.startsWith(line.trim().toLowerCase()));
  return [hits.length ? hits : COMMANDS, line];
}

/**
 * Process single command string
 */
async function processCommand(rawInput) {
  const input = rawInput.trim();
  if (!input) return true;

  const parts = input.split(/\s+/);
  const cmd = parts[0].toLowerCase();
  const arg = parts[1];

  // Direct IP entered (e.g. "1.1.1.1")
  if (geoService.isValidIp(cmd)) {
    await handleLookup(cmd, false);
    return true;
  }

  switch (cmd) {
    case 'help':
    case '?':
      printHelp();
      break;

    case 'lookup':
    case 'info':
      if (!arg) {
        console.log(`${C.yellow}Cách dùng: ${cmd} <ip>${C.reset}`);
      } else {
        await handleLookup(arg, false);
      }
      break;

    case 'raw':
      if (!arg) {
        console.log(`${C.yellow}Cách dùng: raw <ip>${C.reset}`);
      } else {
        await handleLookup(arg, true);
      }
      break;

    case 'threat':
    case 'security':
      if (!arg) {
        console.log(`${C.yellow}Cách dùng: threat <ip>${C.reset}`);
      } else {
        await handleThreat(arg);
      }
      break;

    case 'asn':
      if (!arg) {
        console.log(`${C.yellow}Cách dùng: asn <ip>${C.reset}`);
      } else {
        try {
          const res = geoService.lookup('asn', arg);
          console.log(JSON.stringify(res.data, null, 2));
        } catch (e) {
          console.log(`${C.brightRed}✖ Lỗi:${C.reset} ${e.message}`);
        }
      }
      break;

    case 'city':
    case 'country':
      if (!arg) {
        console.log(`${C.yellow}Cách dùng: ${cmd} <ip>${C.reset}`);
      } else {
        try {
          const res = geoService.lookup(cmd, arg);
          console.log(JSON.stringify(res.data, null, 2));
        } catch (e) {
          console.log(`${C.brightRed}✖ Lỗi:${C.reset} ${e.message}`);
        }
      }
      break;

    case 'status':
      await handleStatus();
      break;

    case 'sync':
      await handleSync(parts.includes('--force'));
      break;

    case 'keys':
      handleKeys();
      break;

    case 'clear':
    case 'cls':
      console.clear();
      printBanner();
      break;

    case 'exit':
    case 'quit':
    case 'q':
      console.log(`\n${C.cyan}Tạm biệt! Hẹn gặp lại bạn.${C.reset}\n`);
      return false;

    default:
      console.log(`${C.yellow}Lệnh không nhận dạng được: '${cmd}'. Gõ 'help' để xem danh sách lệnh.${C.reset}`);
      break;
  }

  return true;
}

/**
 * Main Entry Point
 */
async function main() {
  // Check if databases are loaded into memory
  await geoService.reload({ silent: true });

  // If arguments provided via command line, execute and exit (e.g., node src/cli.js 1.1.1.1)
  const cliArgs = process.argv.slice(2);
  if (cliArgs.length > 0) {
    const fullCmd = cliArgs.join(' ');
    await processCommand(fullCmd);
    process.exit(0);
  }

  // Interactive REPL Mode
  console.clear();
  printBanner();
  console.log(`${C.gray}Gõ ${C.brightCyan}help${C.gray} để xem các lệnh, hoặc nhập trực tiếp địa chỉ IP để phân tích.${C.reset}`);
  console.log(`${C.gray}Nhấn ${C.brightCyan}Tab${C.gray} để gợi ý lệnh, ${C.brightCyan}Ctrl+C${C.gray} hoặc gõ ${C.brightCyan}exit${C.gray} để thoát.${C.reset}\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    completer,
    prompt: `${C.bold}${C.brightCyan}aegis ❯ ${C.reset}`
  });

  rl.prompt();

  rl.on('line', async (line) => {
    try {
      const shouldContinue = await processCommand(line);
      if (!shouldContinue) {
        rl.close();
        process.exit(0);
      }
    } catch (err) {
      console.error(`${C.brightRed}Error:${C.reset}`, err);
    }
    rl.prompt();
  });

  rl.on('close', () => {
    console.log(`\n${C.cyan}Aegis CLI đã đóng.${C.reset}\n`);
    process.exit(0);
  });
}

main();
