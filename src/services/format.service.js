import dns from 'node:dns/promises';
import { config } from '../config.js';
import { MemoryCache } from '../utils/cache.js';
import { geoService } from './geo.service.js';
import { rdapService } from './rdap.service.js';
import { domainsService } from './domains.service.js';
import { threatService } from './threat.service.js';

// Cache for formatted responses, hostnames, and IPInfo fallbacks
const formatCache = new MemoryCache(3600 * 1000, 20000); // 1 hour TTL
const hostnameCache = new MemoryCache(24 * 3600 * 1000, 20000); // 24 hours TTL
const ipinfoCache = new MemoryCache(6 * 3600 * 1000, 10000); // 6 hours TTL

// Known ASNs dictionary for domain, type, and anycast status
const KNOWN_ASNS = {
  13335: { domain: 'cloudflare.com', type: 'hosting', is_anycast: true, is_hosting: true },
  15169: { domain: 'google.com', type: 'hosting', is_anycast: true, is_hosting: true },
  16509: { domain: 'amazon.com', type: 'hosting', is_hosting: true },
  14618: { domain: 'amazon.com', type: 'hosting', is_hosting: true },
  8075:  { domain: 'microsoft.com', type: 'hosting', is_hosting: true },
  14061: { domain: 'digitalocean.com', type: 'hosting', is_hosting: true },
  24940: { domain: 'hetzner.com', type: 'hosting', is_hosting: true },
  16276: { domain: 'ovh.com', type: 'hosting', is_hosting: true },
  20473: { domain: 'vultr.com', type: 'hosting', is_hosting: true },
  63949: { domain: 'linode.com', type: 'hosting', is_hosting: true },
  19281: { domain: 'quad9.net', type: 'business', is_anycast: true },
  36692: { domain: 'opendns.com', type: 'business', is_anycast: true },
  7552:  { domain: 'viettel.com.vn', type: 'isp', is_mobile: true },
  45899: { domain: 'vnpt.vn', type: 'isp' },
  18403: { domain: 'fpt.vn', type: 'isp' }
};

// Fallback mapping for Country Code to Continent
const COUNTRY_TO_CONTINENT = {
  AU: { code: 'OC', name: 'Oceania' },
  NZ: { code: 'OC', name: 'Oceania' },
  US: { code: 'NA', name: 'North America' },
  CA: { code: 'NA', name: 'North America' },
  MX: { code: 'NA', name: 'North America' },
  VN: { code: 'AS', name: 'Asia' },
  JP: { code: 'AS', name: 'Asia' },
  CN: { code: 'AS', name: 'Asia' },
  SG: { code: 'AS', name: 'Asia' },
  KR: { code: 'AS', name: 'Asia' },
  GB: { code: 'EU', name: 'Europe' },
  DE: { code: 'EU', name: 'Europe' },
  FR: { code: 'EU', name: 'Europe' },
  NL: { code: 'EU', name: 'Europe' }
};

/**
 * Reverse DNS resolution with timeout
 */
async function resolveHostname(ip) {
  const cached = hostnameCache.get(`hostname:${ip}`);
  if (cached !== null && cached !== undefined) return cached;

  try {
    const timeoutPromise = new Promise((_, reject) => 
      setTimeout(() => reject(new Error('timeout')), 800)
    );
    const reversePromise = dns.reverse(ip);
    const hostnames = await Promise.race([reversePromise, timeoutPromise]);
    const hostname = hostnames?.[0] || null;
    hostnameCache.set(`hostname:${ip}`, hostname);
    return hostname;
  } catch {
    hostnameCache.set(`hostname:${ip}`, null);
    return null;
  }
}

/**
 * Inspect ASN details (domain, type, hosting/mobile/satellite/anycast)
 */
function inspectAsn(asnNumber, orgName) {
  const normalizedOrg = (orgName || '').toLowerCase();
  const known = KNOWN_ASNS[asnNumber] || {};

  let isHosting = Boolean(known.is_hosting);
  let isMobile = Boolean(known.is_mobile);
  let isSatellite = Boolean(known.is_satellite);
  let isAnycast = Boolean(known.is_anycast);
  let type = known.type || 'isp';
  let domain = known.domain || null;

  if (!domain && orgName) {
    const cleanName = orgName.split(/[,.\s]+/)[0].toLowerCase();
    if (cleanName.length > 2) {
      domain = `${cleanName}.com`;
    }
  }

  const hostingKeywords = /hosting|cloud|datacenter|data\s*center|vps|server|dedicated|compute|amazon|aws|google|microsoft|azure|cloudflare|digitalocean|hetzner|ovh|linode|vultr|alibaba|oracle|leaseweb|choopa|scaleway|contabo|fastly|akamai/i;
  if (!isHosting && hostingKeywords.test(normalizedOrg)) {
    isHosting = true;
    type = 'hosting';
  }

  const mobileKeywords = /mobile|cellular|wireless|telecom|telephony|4g|5g|lte/i;
  if (!isMobile && mobileKeywords.test(normalizedOrg)) {
    isMobile = true;
  }

  const satelliteKeywords = /satellite|starlink|viasat|inmarsat|iridium|eutelsat|oneweb/i;
  if (!isSatellite && satelliteKeywords.test(normalizedOrg)) {
    isSatellite = true;
  }

  return { domain, type, isHosting, isMobile, isSatellite, isAnycast };
}

/**
 * Fetch online enrichment from IPInfo.io if token is configured
 */
async function fetchIpInfo(ip) {
  const token = config.keys.ipinfoToken;
  if (!token) return null;

  const cached = ipinfoCache.get(`ipinfo:${ip}`);
  if (cached) return cached;

  try {
    const res = await fetch(`https://ipinfo.io/${ip}/json?token=${token}`, {
      signal: AbortSignal.timeout(1200)
    });
    if (res.ok) {
      const data = await res.json();
      ipinfoCache.set(`ipinfo:${ip}`, data);
      return data;
    }
  } catch {}
  return null;
}

class FormatService {
  /**
   * Format full IP intelligence data into forms.txt standard schema
   */
  async format(ip, options = {}) {
    const cacheKey = `full_format:${ip}:${Boolean(options.enrich)}`;
    const fullCached = formatCache.get(cacheKey);
    if (fullCached) return fullCached;

    // 1. Gather raw data from local MMDB (instant in-memory)
    const raw = geoService.lookupAll(ip);
    const city = raw.city || {};
    const country = raw.country || {};
    const asn = raw.asn || {};

    const asnNumber = asn.autonomous_system_number || null;
    const orgName = asn.autonomous_system_organization || null;
    const asnInfo = inspectAsn(asnNumber, orgName);

    // 2. Fetch reverse DNS, threat detection, RDAP, and passive DNS in parallel
    const needOnlineEnrich = options.enrich || !city.city || !city.location;
    const shouldCheckThreat = options.enrich !== false;

    const [hostname, threatInfo, onlineIpInfo, rdapData, domainsData] = await Promise.all([
      resolveHostname(ip),
      shouldCheckThreat
        ? threatService.checkThreat(ip)
        : Promise.resolve({
            is_proxy: false,
            is_relay: false,
            is_tor: false,
            is_vpn: false,
            is_res_proxy: false,
            is_anonymous: false,
            is_hosting: false
          }),
      needOnlineEnrich ? fetchIpInfo(ip) : Promise.resolve(null),
      rdapService.getAbuseAndCompany(ip, { name: orgName, domain: asnInfo.domain, type: asnInfo.type }),
      domainsService.getDomains(ip)
    ]);

    // 3. Country & Continent resolution with fallbacks
    const countryName = city.country?.names?.en || 
                        country.country?.names?.en || 
                        city.registered_country?.names?.en || 
                        country.registered_country?.names?.en || 
                        null;

    const countryCode = city.country?.iso_code || 
                        country.country?.iso_code || 
                        city.registered_country?.iso_code || 
                        country.registered_country?.iso_code || 
                        onlineIpInfo?.country || 
                        null;

    let continentName = city.continent?.names?.en || country.continent?.names?.en || null;
    let continentCode = city.continent?.code || country.continent?.code || null;

    if (!continentCode && countryCode && COUNTRY_TO_CONTINENT[countryCode]) {
      continentCode = COUNTRY_TO_CONTINENT[countryCode].code;
      continentName = COUNTRY_TO_CONTINENT[countryCode].name;
    }

    // 4. Coordinates resolution
    let latitude = city.location?.latitude || null;
    let longitude = city.location?.longitude || null;
    if (latitude === null && onlineIpInfo?.loc) {
      const parts = onlineIpInfo.loc.split(',');
      if (parts.length === 2) {
        latitude = parseFloat(parts[0]);
        longitude = parseFloat(parts[1]);
      }
    }

    const cityName = city.city?.names?.en || onlineIpInfo?.city || null;
    const regionName = city.subdivisions?.[0]?.names?.en || onlineIpInfo?.region || null;
    const regionCode = city.subdivisions?.[0]?.iso_code || null;
    const timezone = city.location?.time_zone || onlineIpInfo?.timezone || null;
    const postalCode = city.postal?.code || onlineIpInfo?.postal || null;
    const geonameId = city.city?.geoname_id ? String(city.city.geoname_id) : (city.country?.geoname_id ? String(city.country.geoname_id) : (city.registered_country?.geoname_id ? String(city.registered_country.geoname_id) : null));
    const radius = city.location?.accuracy_radius || (cityName ? 50 : null);

    const isAnycast = Boolean(asnInfo.isAnycast || onlineIpInfo?.anycast);
    const finalHostname = hostname || onlineIpInfo?.hostname || null;

    // Assemble final standardized JSON schema matching forms.txt
    const result = {
      ip,
      hostname: finalHostname,
      geo: {
        city: cityName,
        region: regionName,
        region_code: regionCode,
        country: countryName,
        country_code: countryCode,
        continent: continentName,
        continent_code: continentCode,
        latitude,
        longitude,
        timezone,
        postal_code: postalCode,
        geoname_id: geonameId,
        radius,
        last_changed: new Date().toISOString().split('T')[0]
      },
      place: {},
      as: {
        asn: asnNumber ? `AS${asnNumber}` : null,
        name: orgName,
        domain: asnInfo.domain,
        type: asnInfo.type,
        last_changed: null
      },
      mobile: {},
      anonymous: {
        is_proxy: threatInfo.is_proxy,
        is_relay: threatInfo.is_relay,
        is_tor: threatInfo.is_tor,
        is_vpn: threatInfo.is_vpn,
        is_res_proxy: threatInfo.is_res_proxy
      },
      is_place: false,
      is_anonymous: threatInfo.is_anonymous,
      is_anycast: isAnycast,
      is_hosting: Boolean(asnInfo.isHosting || threatInfo.is_hosting),
      is_mobile: asnInfo.isMobile,
      is_satellite: asnInfo.isSatellite,
      company: rdapData.company,
      abuse: rdapData.abuse,
      domains: domainsData
    };

    formatCache.set(cacheKey, result);
    return result;
  }
}

export const formatService = new FormatService();
