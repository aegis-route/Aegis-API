import { config } from '../config.js';
import { MemoryCache } from '../utils/cache.js';

class DomainsService {
  constructor() {
    this.cache = new MemoryCache(2 * 3600 * 1000, 5000); // 2 hours TTL
  }

  /**
   * Fetch hosted domains for an IP (Passive DNS / Reverse IP Lookup)
   */
  async getDomains(ip) {
    const cacheKey = `domains:${ip}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const defaultResult = {
      ip,
      total: 0,
      domains: []
    };

    // 1. Try VirusTotal resolutions if API key is configured
    if (config.keys.virustotal) {
      try {
        const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}/resolutions?limit=10`, {
          headers: { 'x-apikey': config.keys.virustotal },
          signal: AbortSignal.timeout(2000)
        });
        if (res.ok) {
          const data = await res.json();
          const list = (data.data || [])
            .map(item => item.attributes?.host_name)
            .filter(Boolean);

          if (list.length > 0) {
            const result = {
              ip,
              total: data.meta?.count || list.length,
              domains: list.slice(0, 5)
            };
            this.cache.set(cacheKey, result);
            return result;
          }
        }
      } catch {}
    }

    // 2. Fallback to HackerTarget reverse IP lookup
    try {
      const res = await fetch(`https://api.hackertarget.com/reverseiplookup/?q=${ip}`, {
        signal: AbortSignal.timeout(2000)
      });
      if (res.ok) {
        const text = await res.text();
        if (text && !text.includes('error') && !text.includes('No records') && !text.includes('API count')) {
          const lines = text
            .split('\n')
            .map(s => s.trim())
            .filter(s => s.length > 0 && s.includes('.'));

          if (lines.length > 0) {
            const result = {
              ip,
              total: lines.length,
              domains: lines.slice(0, 5)
            };
            this.cache.set(cacheKey, result);
            return result;
          }
        }
      }
    } catch {}

    this.cache.set(cacheKey, defaultResult);
    return defaultResult;
  }
}

export const domainsService = new DomainsService();
