import fs from 'node:fs';
import path from 'node:path';
import dotenv from 'dotenv';

dotenv.config();

const envConfig = process.env;

const TEST_IP = '8.8.8.8';

const tests = [
  {
    name: 'ProxyCheck.io',
    key: 'PROXYCHECK_KEY',
    run: async (key) => {
      const res = await fetch(`https://proxycheck.io/v2/${TEST_IP}?key=${key}&vpn=1&asn=1&risk=1`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (data.status === 'ok') {
        const info = data[TEST_IP] || {};
        return { ok: true, status: res.status, detail: `ASN: ${info.asn || 'N/A'}, Proxy: ${info.proxy || 'no'}, Provider: ${info.provider || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.message || JSON.stringify(data) };
    }
  },
  {
    name: 'VPNAPI.io',
    key: 'VPNAPI_KEY',
    run: async (key) => {
      const res = await fetch(`https://vpnapi.io/api/${TEST_IP}?key=${key}`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.security) {
        return { ok: true, status: res.status, detail: `VPN: ${data.security.vpn}, Proxy: ${data.security.proxy}, Country: ${data.location?.country || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.message || JSON.stringify(data) };
    }
  },
  {
    name: 'IPHub.info',
    key: 'IPHUB_KEY',
    run: async (key) => {
      const res = await fetch(`https://v2.api.iphub.info/ip/${TEST_IP}`, {
        headers: { 'X-Key': key },
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.block !== undefined) {
        const blockName = data.block === 0 ? 'Residential (0)' : (data.block === 1 ? 'Hosting/VPN (1)' : 'Suspicious (2)');
        return { ok: true, status: res.status, detail: `Block: ${blockName}, Country: ${data.countryName || data.countryCode}, ISP: ${data.isp || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.error || JSON.stringify(data) };
    }
  },
  {
    name: 'GetIPIntel.net',
    key: 'GETIPINTEL_EMAIL',
    run: async (email) => {
      const res = await fetch(`http://check.getipintel.net/check.php?ip=${TEST_IP}&contact=${encodeURIComponent(email)}&format=json&flags=m`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (data.status === 'success') {
        return { ok: true, status: res.status, detail: `Proxy Probability Score: ${data.result} (0-1)` };
      }
      return { ok: false, status: res.status, detail: data.message || JSON.stringify(data) };
    }
  },
  {
    name: 'IPHunter.info',
    key: 'IPHUNTER_KEY',
    run: async (key) => {
      const res = await fetch(`https://www.iphunter.info:8082/v1/ip/${TEST_IP}`, {
        headers: { 'X-Key': key },
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (data.status === 'success' && data.data) {
        const blockName = data.data.block === 0 ? 'Residential (0)' : (data.data.block === 1 ? 'Cloud/Hosting/VPN (1)' : 'Compromised (2)');
        return { ok: true, status: res.status, detail: `Block: ${blockName}, ISP: ${data.data.isp || 'N/A'}, City: ${data.data.city || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.message || JSON.stringify(data) };
    }
  },
  {
    name: 'IPQualityScore.com',
    key: 'IPQUALITYSCORE_KEY',
    run: async (key) => {
      const res = await fetch(`https://www.ipqualityscore.com/api/json/ip/${key}/${TEST_IP}?strictness=0`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (data.success) {
        return { ok: true, status: res.status, detail: `Fraud Score: ${data.fraud_score}/100, Proxy: ${data.proxy}, VPN: ${data.vpn}, Tor: ${data.tor}` };
      }
      return { ok: false, status: res.status, detail: data.message || JSON.stringify(data) };
    }
  },
  {
    name: 'IPInfo.io',
    key: 'IPINFO_TOKEN',
    run: async (token) => {
      const res = await fetch(`https://ipinfo.io/${TEST_IP}/json?token=${token}`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.ip) {
        return { ok: true, status: res.status, detail: `Org: ${data.org || 'N/A'}, City: ${data.city || 'N/A'}, Country: ${data.country || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.error?.message || JSON.stringify(data) };
    }
  },
  {
    name: 'IPGeolocation.io',
    key: 'IPGEOLOCATION_API_KEY',
    run: async (key) => {
      const res = await fetch(`https://api.ipgeolocation.io/ipgeo?apiKey=${key}&ip=${TEST_IP}`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.ip) {
        return { ok: true, status: res.status, detail: `Country: ${data.country_name || 'N/A'}, ISP: ${data.isp || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.message || JSON.stringify(data) };
    }
  },
  {
    name: 'IPData.co',
    key: 'IPDATA_API_KEY',
    run: async (key) => {
      const res = await fetch(`https://api.ipdata.co/${TEST_IP}?api-key=${key}`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.ip) {
        return { ok: true, status: res.status, detail: `Country: ${data.country_name || 'N/A'}, ASN: ${data.asn?.name || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.message || JSON.stringify(data) };
    }
  },
  {
    name: 'AbstractAPI.com',
    key: 'ABSTRACTAPI_API_KEY',
    run: async (key) => {
      const res = await fetch(`https://ipgeolocation.abstractapi.com/v1/?api_key=${key}&ip_address=${TEST_IP}`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.ip_address) {
        return { ok: true, status: res.status, detail: `Country: ${data.country || 'N/A'}, City: ${data.city || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.error?.message || JSON.stringify(data) };
    }
  },
  {
    name: 'IP2Location.io',
    key: 'IP2LOCATION_API_KEY',
    run: async (key) => {
      const res = await fetch(`https://api.ip2location.io/?key=${key}&ip=${TEST_IP}`, {
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.ip) {
        return { ok: true, status: res.status, detail: `Country: ${data.country_name || 'N/A'}, ASN: ${data.asn || 'N/A'}, AS: ${data.as || 'N/A'}` };
      }
      return { ok: false, status: res.status, detail: data.error?.error_message || JSON.stringify(data) };
    }
  },
  {
    name: 'AbuseIPDB.com',
    key: 'ABUSEIPDB_API_KEY',
    run: async (key) => {
      const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${TEST_IP}`, {
        headers: { 'Key': key, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.data) {
        return { ok: true, status: res.status, detail: `Abuse Score: ${data.data.abuseConfidenceScore}%, Total Reports: ${data.data.totalReports}` };
      }
      return { ok: false, status: res.status, detail: data.errors?.[0]?.detail || JSON.stringify(data) };
    }
  },
  {
    name: 'VirusTotal.com',
    key: 'VIRUSTOTAL_API_KEY',
    run: async (key) => {
      const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${TEST_IP}`, {
        headers: { 'x-apikey': key },
        signal: AbortSignal.timeout(10000)
      });
      const data = await res.json();
      if (res.ok && data.data?.attributes) {
        const stats = data.data.attributes.last_analysis_stats || {};
        return { ok: true, status: res.status, detail: `Harmless: ${stats.harmless}, Malicious: ${stats.malicious}, Suspicious: ${stats.suspicious}` };
      }
      return { ok: false, status: res.status, detail: data.error?.message || JSON.stringify(data) };
    }
  }
];

async function main() {
  console.log(`🔍 Bắt đầu kiểm tra ${tests.length} API keys trong .env với IP mục tiêu: ${TEST_IP}\n`);
  
  const results = [];

  for (const t of tests) {
    const val = envConfig[t.key];
    if (!val || val.trim() === '') {
      results.push({ name: t.name, keyName: t.key, status: 'SKIPPED', detail: 'Chưa cấu hình key' });
      continue;
    }

    const start = Date.now();
    try {
      const res = await t.run(val.trim());
      const duration = Date.now() - start;
      results.push({
        name: t.name,
        keyName: t.key,
        status: res.ok ? 'SUCCESS' : 'FAILED',
        httpStatus: res.status,
        duration: `${duration}ms`,
        detail: res.detail
      });
    } catch (err) {
      const duration = Date.now() - start;
      results.push({
        name: t.name,
        keyName: t.key,
        status: 'ERROR',
        httpStatus: 'ERR',
        duration: `${duration}ms`,
        detail: err.message
      });
    }
  }

  console.log(JSON.stringify(results, null, 2));
}

main();
