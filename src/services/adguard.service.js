import { config } from '../config.js';

export class AdGuardService {
  constructor() {
    this.baseUrl = (config.adguard?.url || 'http://10.10.100.2:80').replace(/\/+$/, '');
    this.username = config.adguard?.user || 'minhmcpc';
    this.password = config.adguard?.pass || '2011';
    this.authHeader = 'Basic ' + Buffer.from(`${this.username}:${this.password}`).toString('base64');
  }

  getHeaders() {
    return {
      Authorization: this.authHeader,
      'Content-Type': 'application/json',
      Accept: 'application/json'
    };
  }

  /**
   * Helper fetch with timeout
   */
  async request(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeout || 2500);

    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        ...options,
        headers: {
          ...this.getHeaders(),
          ...options.headers
        },
        signal: controller.signal
      });
      clearTimeout(timeout);
      return res;
    } catch (err) {
      clearTimeout(timeout);
      throw err;
    }
  }

  /**
   * Kiểm tra máy chủ AdGuard Home có đang kết nối được không
   */
  async isOnline() {
    try {
      const res = await this.request('/control/status', { timeout: 1500 });
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * Lấy trạng thái hoạt động của AdGuard Home
   */
  async getStatus() {
    try {
      const res = await this.request('/control/status');
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('[AdGuard] getStatus failed:', err.message);
    }
    return null;
  }

  /**
   * Lấy số liệu thống kê truy vấn thời gian thực
   */
  async getStats() {
    try {
      const res = await this.request('/control/stats');
      if (res.ok) {
        const raw = await res.json();
        const queriesTotal = raw.num_dns_queries || 0;
        const blockedTotal = raw.num_blocked_filtering || 0;
        const blockedPercent = queriesTotal > 0
          ? +((blockedTotal / queriesTotal) * 100).toFixed(1)
          : 0;
        const avgLatencyMs = +((raw.avg_processing_time || 0) * 1000).toFixed(2);

        return {
          queriesTotal,
          blockedTotal,
          blockedPercent,
          avgLatencyMs,
          rulesCount: 185513, // AdGuard DNS filter count
          topBlockedDomains: raw.top_blocked_domains || [],
          topClients: raw.top_clients || [],
          topQueriedDomains: raw.top_queried_domains || [],
          topUpstreamsResponses: raw.top_upstreams_responses || []
        };
      }
    } catch (err) {
      console.warn('[AdGuard] getStats failed:', err.message);
    }
    return null;
  }

  /**
   * Lấy danh sách ID các dịch vụ đang bị chặn trong AdGuard
   */
  async getBlockedServices() {
    try {
      const res = await this.request('/control/blocked_services/list');
      if (res.ok) {
        const list = await res.json();
        return Array.isArray(list) ? list : [];
      }
    } catch (err) {
      console.warn('[AdGuard] getBlockedServices failed:', err.message);
    }
    return null;
  }

  /**
   * Cập nhật toàn bộ danh sách dịch vụ bị chặn
   */
  async setBlockedServices(ids) {
    try {
      const payload = {
        ids: Array.from(new Set(ids)),
        schedule: { time_zone: 'Local' }
      };
      const res = await this.request('/control/blocked_services/update', {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      return res.ok;
    } catch (err) {
      console.warn('[AdGuard] setBlockedServices failed:', err.message);
      return false;
    }
  }

  /**
   * Bật hoặc tắt chặn một dịch vụ cụ thể
   */
  async toggleService(serviceId, blocked) {
    try {
      const currentList = (await this.getBlockedServices()) || [];
      const isCurrentlyBlocked = currentList.includes(serviceId);
      const shouldBlock = typeof blocked === 'boolean' ? blocked : !isCurrentlyBlocked;

      let nextList = [...currentList];
      if (shouldBlock) {
        if (!nextList.includes(serviceId)) {
          nextList.push(serviceId);
        }
      } else {
        nextList = nextList.filter((id) => id !== serviceId);
      }

      const success = await this.setBlockedServices(nextList);
      return {
        success,
        id: serviceId,
        blocked: shouldBlock,
        currentList: nextList
      };
    } catch (err) {
      console.warn('[AdGuard] toggleService failed:', err.message);
      return { success: false, id: serviceId, blocked: false };
    }
  }

  /**
   * Lấy danh sách DNS Rewrites nội bộ từ AdGuard
   */
  async getRewrites() {
    try {
      const res = await this.request('/control/rewrite/list');
      if (res.ok) {
        const list = await res.json();
        return (Array.isArray(list) ? list : []).map((item, idx) => ({
          id: `rw-${idx + 1}`,
          domain: item.domain,
          answer: item.answer,
          type: 'A',
          enabled: item.enabled !== false,
          description: `AdGuard Internal Rewrite (${item.domain} -> ${item.answer})`
        }));
      }
    } catch (err) {
      console.warn('[AdGuard] getRewrites failed:', err.message);
    }
    return null;
  }

  /**
   * Thêm một bản ghi DNS Rewrite vào AdGuard
   */
  async addRewrite({ domain, answer }) {
    try {
      const res = await this.request('/control/rewrite/add', {
        method: 'POST',
        body: JSON.stringify({ domain: domain.trim(), answer: answer.trim() })
      });
      return res.ok;
    } catch (err) {
      console.warn('[AdGuard] addRewrite failed:', err.message);
      return false;
    }
  }

  /**
   * Xóa bản ghi DNS Rewrite khỏi AdGuard
   */
  async deleteRewrite({ domain, answer }) {
    try {
      const res = await this.request('/control/rewrite/delete', {
        method: 'POST',
        body: JSON.stringify({ domain: domain.trim(), answer: answer.trim() })
      });
      return res.ok;
    } catch (err) {
      console.warn('[AdGuard] deleteRewrite failed:', err.message);
      return false;
    }
  }

  /**
   * Lấy danh sách DNS Query Log thời gian thực
   */
  async getQueryLog(filter, limit = 50) {
    try {
      const res = await this.request(`/control/querylog?limit=${limit}`);
      if (res.ok) {
        const json = await res.json();
        const rawLogs = json.data || [];

        const formatted = rawLogs.map((item, idx) => {
          const isBlocked =
            item.reason?.includes('Filtered') ||
            item.reason?.includes('Block') ||
            item.answer?.[0]?.value === '0.0.0.0';
          const isRewritten = item.reason === 'Rewrite';

          let clientName = item.client_info?.name || '';
          if (!clientName) {
            if (item.client === '10.10.1.199') clientName = 'Aegis-UbuntuClient (VM 105)';
            else if (item.client === '10.10.100.1') clientName = 'MikroTik Gateway (VM 102)';
            else if (item.client === '127.0.0.1') clientName = 'AdGuard Local Host';
            else clientName = `LAN Client (${item.client})`;
          }

          const qType = item.question?.type || 'A';
          const domain = item.question?.name || 'unknown.domain';
          const elapsed = parseFloat(item.elapsedMs) || 0.1;

          return {
            id: `adg-log-${Date.parse(item.time) || Date.now()}-${idx}`,
            time: item.time
              ? new Date(item.time).toLocaleTimeString('vi-VN', { hour12: false })
              : new Date().toLocaleTimeString('vi-VN', { hour12: false }),
            domain,
            clientIp: item.client || '127.0.0.1',
            clientName,
            type: qType,
            status: isBlocked ? 'BLOCKED' : isRewritten ? 'REWRITTEN' : 'RESOLVED',
            responseTime: `${elapsed.toFixed(2)} ms`
          };
        });

        if (filter === 'BLOCKED') {
          return formatted.filter((l) => l.status === 'BLOCKED');
        } else if (filter === 'RESOLVED') {
          return formatted.filter((l) => l.status === 'RESOLVED');
        }
        return formatted;
      }
    } catch (err) {
      console.warn('[AdGuard] getQueryLog failed:', err.message);
    }
    return null;
  }
}

export const adguardService = new AdGuardService();
