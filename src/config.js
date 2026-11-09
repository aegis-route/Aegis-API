import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

dotenv.config({ path: path.join(projectRoot, '.env') });

const dataDirEnv = process.env.DATA_DIR || './data';
const dataDir = path.isAbsolute(dataDirEnv) ? dataDirEnv : path.resolve(projectRoot, dataDirEnv);

export const config = {
  projectRoot,
  port: parseInt(process.env.PORT || '3000', 10),
  host: process.env.HOST || '0.0.0.0',
  dataDir,
  syncCron: process.env.SYNC_CRON || '0 */1 * * *',
  syncOnStartup: process.env.SYNC_ON_STARTUP !== 'false',
  syncApiKey: process.env.SYNC_API_KEY || 'aegis-secret-sync-key',
  githubToken: process.env.GITHUB_TOKEN || '',

  dbFiles: {
    asn: 'GeoLite2-ASN.mmdb',
    city: 'GeoLite2-City.mmdb',
    country: 'GeoLite2-Country.mmdb'
  },

  github: {
    owner: 'P3TERX',
    repo: 'GeoLite.mmdb',
    apiUrl: 'https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest',
    downloadBaseUrl: 'https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download'
  },

  keys: {
    proxycheck: process.env.PROXYCHECK_KEY || '',
    vpnapi: process.env.VPNAPI_KEY || '',
    iphub: process.env.IPHUB_KEY || '',
    getipintelEmail: process.env.GETIPINTEL_EMAIL || '',
    iphunter: process.env.IPHUNTER_KEY || '',
    ipqualityscore: process.env.IPQUALITYSCORE_KEY || '',
    ipinfoToken: process.env.IPINFO_TOKEN || '',
    ipgeolocation: process.env.IPGEOLOCATION_API_KEY || '',
    ipdata: process.env.IPDATA_API_KEY || '',
    abstractapi: process.env.ABSTRACTAPI_API_KEY || '',
    ip2location: process.env.IP2LOCATION_API_KEY || '',
    abuseipdb: process.env.ABUSEIPDB_API_KEY || '',
    virustotal: process.env.VIRUSTOTAL_API_KEY || ''
  },

  adguard: {
    url: process.env.ADGUARD_URL || 'http://10.10.100.2:80',
    user: process.env.ADGUARD_USER || 'admin',
    pass: process.env.ADGUARD_PASS || ''
  }
};
