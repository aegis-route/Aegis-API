import { config } from '../config.js';
import { MemoryCache } from '../utils/cache.js';

class ThreatService {
  constructor() {
    // Cache threat analysis for 1 hour
    this.cache = new MemoryCache(3600 * 1000, 20000);
  }

  /**
   * Check IP against threat engines (VPNAPI, ProxyCheck, IPHub, IPHunter) in parallel
   */
  async checkThreat(ip) {
    const cached = this.cache.get(`threat:${ip}`);
    if (cached) return cached;

    const result = {
      is_proxy: false,
      is_relay: false,
      is_tor: false,
      is_vpn: false,
      is_res_proxy: false,
      is_anonymous: false,
      is_hosting: false
    };

    const checks = [];

    // 1. VPNAPI.io
    if (config.keys.vpnapi) {
      checks.push(
        fetch(`https://vpnapi.io/api/${ip}?key=${config.keys.vpnapi}`, {
          signal: AbortSignal.timeout(1500)
        })
          .then((res) => (res.ok ? res.json() : null))
          .then((data) => {
            if (data?.security) {
              if (data.security.vpn) result.is_vpn = true;
              if (data.security.proxy) result.is_proxy = true;
              if (data.security.tor) result.is_tor = true;
              if (data.security.relay) result.is_relay = true;
            }
          })
          .catch(() => {})
      );
    }

    // 2. ProxyCheck.io
    if (config.keys.proxycheck) {
      checks.push(
        fetch(`https://proxycheck.io/v2/${ip}?key=${config.keys.proxycheck}&vpn=1`, {
          signal: AbortSignal.timeout(1500)
        })
          .then((res) => (res.ok ? res.json() : null))
          .then((data) => {
            const info = data?.[ip];
            if (info) {
              if (info.proxy === 'yes') result.is_proxy = true;
              if (info.type === 'VPN') result.is_vpn = true;
              if (info.type === 'TOR') result.is_tor = true;
              if (info.is_res_proxy) result.is_res_proxy = true;
            }
          })
          .catch(() => {})
      );
    }

    // 3. IPHub.info
    if (config.keys.iphub) {
      checks.push(
        fetch(`https://v2.api.iphub.info/ip/${ip}`, {
          headers: { 'X-Key': config.keys.iphub },
          signal: AbortSignal.timeout(1200)
        })
          .then((res) => (res.ok ? res.json() : null))
          .then((data) => {
            if (data?.block === 1) {
              result.is_vpn = true;
              result.is_proxy = true;
              result.is_hosting = true;
            }
          })
          .catch(() => {})
      );
    }

    // 4. IPHunter.info
    if (config.keys.iphunter) {
      checks.push(
        fetch(`https://www.iphunter.info:8082/v1/ip/${ip}`, {
          headers: { 'X-Key': config.keys.iphunter },
          signal: AbortSignal.timeout(1500)
        })
          .then((res) => (res.ok ? res.json() : null))
          .then((data) => {
            if (data?.status === 'success' && data?.data?.block === 1) {
              result.is_vpn = true;
              result.is_proxy = true;
              result.is_hosting = true;
            }
          })
          .catch(() => {})
      );
    }

    // Run all configured checks concurrently
    if (checks.length > 0) {
      await Promise.allSettled(checks);
    }

    result.is_anonymous = Boolean(
      result.is_proxy ||
      result.is_relay ||
      result.is_tor ||
      result.is_vpn ||
      result.is_res_proxy
    );

    this.cache.set(`threat:${ip}`, result);
    return result;
  }
}

export const threatService = new ThreatService();
