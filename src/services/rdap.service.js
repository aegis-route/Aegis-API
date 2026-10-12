import { MemoryCache } from '../utils/cache.js';

class RdapService {
  constructor() {
    this.cache = new MemoryCache(24 * 3600 * 1000, 10000); // 24 hours TTL
  }

  /**
   * Fetch company and abuse contact information via RIPEstat REST API
   */
  async getAbuseAndCompany(ip, defaultAsn = {}) {
    const cacheKey = `whois_abuse:${ip}`;
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    const defaultResult = {
      company: {
        name: defaultAsn.name || null,
        domain: defaultAsn.domain || null,
        type: defaultAsn.type || 'hosting'
      },
      abuse: {
        address: null,
        country: null,
        email: null,
        name: null,
        network: null,
        phone: null
      }
    };

    try {
      const res = await fetch(`https://stat.ripe.net/data/whois/data.json?resource=${ip}`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(3000)
      });

      if (!res.ok) {
        this.cache.set(cacheKey, defaultResult);
        return defaultResult;
      }

      const data = await res.json();
      const records = data.data?.records || [];

      const pairs = {};
      const descriptions = [];
      const addressLines = [];

      for (const group of records) {
        if (!Array.isArray(group)) continue;
        for (const item of group) {
          const k = (item.key || '').toLowerCase();
          const v = item.value || '';
          if (!pairs[k]) pairs[k] = v;

          if (k === 'descr') descriptions.push(v);
          if (k === 'address') addressLines.push(v);
        }
      }

      // 1. Company Name
      const companyName = descriptions[0] ||
                          pairs['organization'] ||
                          pairs['netname'] ||
                          defaultAsn.name ||
                          null;

      // 2. Abuse Info
      const network = pairs['cidr'] || pairs['inetnum'] || pairs['netrange'] || null;
      const country = pairs['country'] || pairs['country-code'] || null;
      const email = pairs['orgabuseemail'] || pairs['abuse-mailbox'] || pairs['e-mail'] || pairs['email'] || null;
      const phone = pairs['orgabusephone'] || pairs['phone'] || '+000000000';
      const address = addressLines.length > 0 ? addressLines.join(', ') : (pairs['orgabuseaddress'] || null);

      let abuseName = null;
      if (pairs['mnt-irt']) {
        abuseName = `ABUSE ${pairs['mnt-irt'].replace(/[^A-Za-z0-9]/g, '')}`;
      } else if (pairs['orgabusehandle']) {
        abuseName = `ABUSE ${pairs['orgabusehandle'].replace(/[^A-Za-z0-9]/g, '')}`;
      } else if (pairs['orgabusename']) {
        abuseName = pairs['orgabusename'];
      }

      // If email is missing, query abuse-contact-finder as fallback
      let finalEmail = email;
      if (!finalEmail) {
        try {
          const abuseFinderRes = await fetch(`https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${ip}`, {
            signal: AbortSignal.timeout(1500)
          });
          if (abuseFinderRes.ok) {
            const finderData = await abuseFinderRes.json();
            const contacts = finderData.data?.abuse_contacts || [];
            if (contacts.length > 0) {
              finalEmail = contacts[0];
            }
          }
        } catch {}
      }

      const result = {
        company: {
          name: companyName,
          domain: defaultAsn.domain || null,
          type: defaultAsn.type || 'hosting'
        },
        abuse: {
          address,
          country,
          email: finalEmail,
          name: abuseName,
          network,
          phone
        }
      };

      this.cache.set(cacheKey, result);
      return result;
    } catch {
      this.cache.set(cacheKey, defaultResult);
      return defaultResult;
    }
  }
}

export const rdapService = new RdapService();
