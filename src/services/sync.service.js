import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import cron from 'node-cron';
import maxmind from 'maxmind';
import { config } from '../config.js';
import { geoService } from './geo.service.js';

class SyncService {
  constructor() {
    this.isSyncing = false;
    this.lastSyncTime = null;
    this.lastSyncResult = null;
    this.metadataFile = path.join(config.dataDir, 'metadata.json');
    this.tmpDir = path.join(config.dataDir, 'tmp');
    this.cronTask = null;
  }

  /**
   * Read stored metadata
   */
  async getMetadata() {
    try {
      const content = await fs.readFile(this.metadataFile, 'utf8');
      return JSON.parse(content);
    } catch {
      return null;
    }
  }

  /**
   * Save metadata to disk
   */
  async saveMetadata(data) {
    try {
      await fs.writeFile(this.metadataFile, JSON.stringify(data, null, 2), 'utf8');
    } catch (err) {
      console.error('[SyncService] Failed to save metadata:', err.message);
    }
  }

  /**
   * Fetch latest release info from GitHub API or fallback
   */
  async fetchLatestReleaseInfo() {
    const headers = {
      'User-Agent': 'Aegis-API'
    };
    if (config.githubToken) {
      headers.Authorization = `Bearer ${config.githubToken}`;
    }

    try {
      const res = await fetch(config.github.apiUrl, { headers });
      if (res.ok) {
        const data = await res.json();
        return {
          tag: data.tag_name || data.name,
          publishedAt: data.published_at,
          source: 'github-api'
        };
      }
      console.warn(`[SyncService] GitHub API returned status ${res.status}, using header fallback.`);
    } catch (err) {
      console.warn(`[SyncService] GitHub API request failed (${err.message}), using fallback.`);
    }

    // Fallback: Check HEAD of ASN release asset for ETag / Last-Modified
    try {
      const fallbackUrl = `${config.github.downloadBaseUrl}/${config.dbFiles.asn}`;
      const headRes = await fetch(fallbackUrl, {
        method: 'HEAD',
        redirect: 'follow',
        headers: { 'User-Agent': 'Aegis-API' }
      });
      const lastModified = headRes.headers.get('last-modified') || headRes.headers.get('etag') || new Date().toISOString();
      return {
        tag: `fallback-${lastModified}`,
        publishedAt: lastModified,
        source: 'http-head'
      };
    } catch (err) {
      console.error(`[SyncService] Fallback check failed: ${err.message}`);
      return {
        tag: `unknown-${Date.now()}`,
        publishedAt: null,
        source: 'unknown'
      };
    }
  }

  /**
   * Download a single file with streaming pipeline
   */
  async downloadFile(url, destPath) {
    const res = await fetch(url, {
      redirect: 'follow',
      headers: { 'User-Agent': 'Aegis-API' }
    });

    if (!res.ok) {
      throw new Error(`Failed to download ${url}: HTTP ${res.status} ${res.statusText}`);
    }

    if (!res.body) {
      throw new Error(`Empty response body for ${url}`);
    }

    await pipeline(Readable.fromWeb(res.body), createWriteStream(destPath));
  }

  /**
   * Check if any required database file is missing
   */
  async hasMissingFiles() {
    for (const key of ['asn', 'city', 'country']) {
      const filename = config.dbFiles[key];
      const filePath = path.join(config.dataDir, filename);
      try {
        const stats = await fs.stat(filePath);
        if (stats.size === 0) return true;
      } catch {
        return true;
      }
    }
    return false;
  }

  /**
   * Check for updates and sync database files
   */
  async sync(force = false) {
    if (this.isSyncing) {
      return {
        success: false,
        message: 'A sync task is already in progress.',
        isSyncing: true
      };
    }

    this.isSyncing = true;
    const startTime = Date.now();

    try {
      await fs.mkdir(config.dataDir, { recursive: true });
      await fs.mkdir(this.tmpDir, { recursive: true });

      const missing = await this.hasMissingFiles();
      const metadata = await this.getMetadata();
      const releaseInfo = await this.fetchLatestReleaseInfo();

      console.log(`[SyncService] Latest upstream release tag: ${releaseInfo.tag} (current: ${metadata?.releaseTag || 'none'})`);

      if (!force && !missing && metadata?.releaseTag && metadata.releaseTag === releaseInfo.tag) {
        this.isSyncing = false;
        this.lastSyncTime = new Date().toISOString();
        this.lastSyncResult = {
          success: true,
          updated: false,
          message: 'Databases are already up to date.',
          releaseTag: releaseInfo.tag
        };
        console.log(`[SyncService] Databases are up to date (tag: ${releaseInfo.tag}). No download needed.`);
        return this.lastSyncResult;
      }

      console.log(`[SyncService] Starting download of GeoLite2 databases (force=${force}, missing=${missing})...`);

      const targets = [
        { key: 'asn', filename: config.dbFiles.asn },
        { key: 'city', filename: config.dbFiles.city },
        { key: 'country', filename: config.dbFiles.country }
      ];

      const downloadedFiles = [];

      // Download all targets to tmp directory
      for (const target of targets) {
        const downloadUrl = `${config.github.downloadBaseUrl}/${target.filename}`;
        const tmpFilePath = path.join(this.tmpDir, `${target.filename}.tmp`);

        console.log(`[SyncService] Downloading ${target.filename}...`);
        await this.downloadFile(downloadUrl, tmpFilePath);

        const stats = await fs.stat(tmpFilePath);
        console.log(`[SyncService] Downloaded ${target.filename}: ${(stats.size / 1024 / 1024).toFixed(2)} MB`);

        // Validate MMDB file integrity
        try {
          const testReader = await maxmind.open(tmpFilePath);
          // Verify with a test query
          testReader.get('8.8.8.8');
        } catch (validateErr) {
          throw new Error(`Corrupted MMDB file ${target.filename}: ${validateErr.message}`);
        }

        downloadedFiles.push({
          key: target.key,
          filename: target.filename,
          tmpPath: tmpFilePath,
          size: stats.size
        });
      }

      // Atomic rename all files to final destination
      const filesSummary = {};
      for (const item of downloadedFiles) {
        const destPath = path.join(config.dataDir, item.filename);
        await fs.rename(item.tmpPath, destPath);
        filesSummary[item.key] = {
          filename: item.filename,
          size: item.size,
          updatedAt: new Date().toISOString()
        };
      }

      // Update metadata
      const newMetadata = {
        lastSync: new Date().toISOString(),
        releaseTag: releaseInfo.tag,
        publishedAt: releaseInfo.publishedAt,
        files: filesSummary
      };
      await this.saveMetadata(newMetadata);

      // Hot reload the GeoService readers
      console.log('[SyncService] Reloading in-memory GeoLite readers...');
      await geoService.reload();

      const durationMs = Date.now() - startTime;
      console.log(`[SyncService] Sync completed successfully in ${(durationMs / 1000).toFixed(1)}s!`);

      this.lastSyncTime = newMetadata.lastSync;
      this.lastSyncResult = {
        success: true,
        updated: true,
        durationMs,
        releaseTag: releaseInfo.tag,
        files: filesSummary,
        message: 'Databases successfully updated and reloaded.'
      };

      return this.lastSyncResult;
    } catch (err) {
      console.error('[SyncService] Sync failed:', err.message);
      this.lastSyncResult = {
        success: false,
        error: err.message,
        timestamp: new Date().toISOString()
      };
      throw err;
    } finally {
      this.isSyncing = false;
      // Clean up tmp directory if any leftover files
      try {
        const tmpFiles = await fs.readdir(this.tmpDir);
        for (const f of tmpFiles) {
          await fs.unlink(path.join(this.tmpDir, f)).catch(() => {});
        }
      } catch {}
    }
  }

  /**
   * Stop scheduled cron task
   */
  stopSchedule() {
    if (this.cronTask) {
      this.cronTask.stop();
      this.cronTask = null;
    }
  }

  /**
   * Start cron scheduler and startup sync check
   */
  startSchedule() {
    this.stopSchedule();

    if (config.syncCron) {
      console.log(`[SyncService] Registering cron schedule: '${config.syncCron}'`);
      this.cronTask = cron.schedule(config.syncCron, async () => {
        console.log('[SyncService] Running scheduled database sync check...');
        try {
          await this.sync(false);
        } catch (err) {
          console.error('[SyncService] Scheduled sync failed:', err.message);
        }
      });
    }

    if (config.syncOnStartup) {
      console.log('[SyncService] Checking databases on startup...');
      setImmediate(async () => {
        try {
          const missing = await this.hasMissingFiles();
          if (missing) {
            console.log('[SyncService] Missing database files detected. Downloading now...');
            await this.sync(true);
          } else {
            console.log('[SyncService] Local database files found. Loading into memory...');
            await geoService.reload();
            // Background check if updates are available
            await this.sync(false);
          }
        } catch (err) {
          console.error('[SyncService] Startup sync check error:', err.message);
        }
      });
    }
  }

  /**
   * Get sync status overview
   */
  async getStatus() {
    const metadata = await this.getMetadata();
    return {
      isSyncing: this.isSyncing,
      lastSyncTime: this.lastSyncTime || metadata?.lastSync || null,
      currentReleaseTag: metadata?.releaseTag || null,
      cronSchedule: config.syncCron,
      lastResult: this.lastSyncResult
    };
  }
}

export const syncService = new SyncService();
