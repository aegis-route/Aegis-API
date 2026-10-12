import fs from 'node:fs/promises';
import path from 'node:path';
import maxmind from 'maxmind';
import { config } from '../config.js';

class GeoService {
  constructor() {
    this.readers = {
      asn: null,
      city: null,
      country: null
    };
    this.status = {
      asn: { loaded: false, file: config.dbFiles.asn, size: 0, lastModified: null },
      city: { loaded: false, file: config.dbFiles.city, size: 0, lastModified: null },
      country: { loaded: false, file: config.dbFiles.country, size: 0, lastModified: null }
    };
  }

  /**
   * Load or reload all available MMDB databases into memory
   */
  async reload(options = {}) {
    const types = ['asn', 'city', 'country'];
    const newReaders = {};

    for (const type of types) {
      const filename = config.dbFiles[type];
      const filePath = path.join(config.dataDir, filename);

      try {
        const stats = await fs.stat(filePath);
        if (stats.size > 0) {
          const reader = await maxmind.open(filePath);
          newReaders[type] = reader;
          this.status[type] = {
            loaded: true,
            file: filename,
            size: stats.size,
            lastModified: stats.mtime.toISOString()
          };
          if (!options.silent) {
            console.log(`[GeoService] Successfully loaded ${filename} (${(stats.size / 1024 / 1024).toFixed(2)} MB)`);
          }
        } else {
          newReaders[type] = null;
          this.status[type].loaded = false;
        }
      } catch (err) {
        newReaders[type] = null;
        this.status[type].loaded = false;
        console.warn(`[GeoService] ${filename} not found or unreadable: ${err.message}`);
      }
    }

    // Atomic replacement of readers
    this.readers = newReaders;
    return this.status;
  }

  /**
   * Validate IP address format (IPv4 or IPv6)
   */
  isValidIp(ip) {
    return maxmind.validate(ip);
  }

  /**
   * Lookup single type for given IP
   */
  lookup(type, ip) {
    const normalizedType = type.toLowerCase();
    if (!['asn', 'city', 'country'].includes(normalizedType)) {
      const err = new Error(`Invalid type '${type}'. Allowed types are 'asn', 'city', 'country', 'all'.`);
      err.statusCode = 400;
      throw err;
    }

    if (!this.isValidIp(ip)) {
      const err = new Error(`Invalid IP address '${ip}'. Must be a valid IPv4 or IPv6 address.`);
      err.statusCode = 400;
      throw err;
    }

    const reader = this.readers[normalizedType];
    if (!reader) {
      const err = new Error(`Database '${config.dbFiles[normalizedType]}' is not currently loaded. Please sync database first.`);
      err.statusCode = 503;
      throw err;
    }

    const data = reader.get(ip);
    return {
      success: true,
      ip,
      type: normalizedType,
      found: Boolean(data),
      data: data || null
    };
  }

  /**
   * Lookup combined ASN, City, Country for given IP
   */
  lookupAll(ip) {
    if (!this.isValidIp(ip)) {
      const err = new Error(`Invalid IP address '${ip}'. Must be a valid IPv4 or IPv6 address.`);
      err.statusCode = 400;
      throw err;
    }

    const result = {
      success: true,
      ip,
      asn: null,
      city: null,
      country: null
    };

    if (this.readers.asn) {
      result.asn = this.readers.asn.get(ip) || null;
    }
    if (this.readers.city) {
      result.city = this.readers.city.get(ip) || null;
    }
    if (this.readers.country) {
      result.country = this.readers.country.get(ip) || null;
    }

    return result;
  }

  /**
   * Get current loaded database status
   */
  getStatus() {
    return this.status;
  }
}

export const geoService = new GeoService();
