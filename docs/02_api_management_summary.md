# Báo Cáo Nghiệm Thu Triển Khai Quản Trị Hệ Thống Aegis-API (Low-Tech / Zero-Setup)

## Phân hệ phụ trách: `Aegis-API`
- **Kỹ sư phụ trách:** api-engineer
- **Mã nguồn:** `/home/minhmcpc/Projects/Aegis-API`
- **Thời gian nghiệm thu:** 2026-10-30
- **Trạng thái:** Hoàn tất 100% - Sẵn sàng tích hợp Aegis-Panel và KernelFW

---

## 1. Cơ Chế Lưu Trữ Đơn Giản (Low-Tech / Zero-Config Persistence)
- **Tệp dịch vụ:** `/home/minhmcpc/Projects/Aegis-API/src/services/store.service.js`
- **Thư mục lưu trữ:** `/home/minhmcpc/Projects/Aegis-API/data/store/`
- **Các tệp JSON quản trị:**
  1. `firewall.json`: 16 Module mitigation tầng eBPF/XDP, danh sách Auto-ban blacklist, quy tắc CIDR LPM Trie.
  2. `router.json`: DHCP Client Leases, FastTrack state, NAT Port Forwarding rules, PPPoE ISP Profiles, active Conntrack connections.
  3. `dns.json`: 11 dịch vụ kiểm soát nội dung (AdGuard Home), chỉ số thống kê DNS, DNS Rewrites nội bộ, Query Logs.
  4. `telemetry.json`: Throughput Mbps, PPS, Total Drops, Active Sessions, trạng thái Emergency Lockdown.
  5. `vault.json`: Danh sách snapshot sao lưu mã hóa hệ thống.
  6. `audit.json`: Lịch sử kiểm toán nhật ký vận hành (tối đa 200 bản ghi mới nhất).
- **Cơ chế tự phục hồi (Self-Healing & Auto-Init):**
  - Tự động kiểm tra và khởi tạo thư mục `data/store/` cùng các file JSON mang preset chuẩn ban đầu từ hệ sinh thái Aegis nếu chưa tồn tại.
  - Hỗ trợ cập nhật và đồng bộ hai chiều: mọi thay đổi từ API được lưu trực tiếp dạng human-readable JSON; đồng thời hỗ trợ biên tập thủ công bằng text editor mà không cần migration hay cơ sở dữ liệu ngoài.

---

## 2. Fastify Route Plugin (`management.routes.js`)
- **Tệp route:** `/home/minhmcpc/Projects/Aegis-API/src/routes/management.routes.js`
- **Đăng ký đa tiền tố (Multi-Prefix Routing):**
  - Hỗ trợ chuẩn REST: `/api/v1/*`
  - Hỗ trợ trực tiếp cho Aegis-Panel BFF: `/api/*`
  - Hỗ trợ gọi trực tiếp: `/*`

### Chi tiết các Endpoint Nghiệm Thu:
| Phân hệ | Endpoint | Phương thức | Mô tả & Chức năng |
| :--- | :--- | :--- | :--- |
| **Tường lửa** | `/api/v1/firewall/modules` | `GET` | Trả về 16 module mitigation, activeCount, tổng số drops/pps |
| | `/api/v1/firewall/modules` | `PATCH` / `POST` | Chuyển đổi mode (`DROP`, `MONITOR`, `OFF`) và status module |
| | `/api/v1/firewall/bans` | `GET` | Danh sách IP bị Auto-Ban trên Kernel eBPF Map |
| | `/api/v1/firewall/bans` | `POST` | Khóa IP mới hoặc mở khóa IP (`action: 'unban'`) |
| | `/api/v1/firewall/bans/:id` | `DELETE` | Gỡ ban IP khỏi danh sách theo ID hoặc query IP |
| | `/api/v1/firewall/cidr` | `GET` | Danh sách quy tắc subnet CIDR |
| | `/api/v1/firewall/cidr` | `POST` | Thêm mới quy tắc subnet CIDR vào eBPF Map |
| | `/api/v1/firewall/cidr/:id` | `DELETE` | Xóa quy tắc CIDR |
| **Mạng & NAT** | `/api/v1/router/leases` | `GET` | Danh sách DHCP Client Leases từ RouterOS |
| | `/api/v1/router/leases/fasttrack` | `PATCH` / `POST` | Bật/tắt tăng tốc phần cứng FastTrack cho client |
| | `/api/v1/router/pppoe` | `GET` | Danh sách profile kết nối ISP WAN (FPT, Viettel, VNPT) |
| | `/api/v1/router/pppoe` | `POST` | Thêm mới profile PPPoE |
| | `/api/v1/router/pppoe/:id` | `PUT` | Cập nhật cấu hình kết nối PPPoE |
| | `/api/v1/router/pppoe/:id` | `DELETE` | Xóa kết nối PPPoE |
| | `/api/v1/router/nat` | `GET` | Danh sách quy tắc NAT Port Forwarding |
| | `/api/v1/router/nat` | `POST` | Thêm mới hoặc toggle (`action: 'toggle'`) quy tắc NAT |
| | `/api/v1/router/nat/:id` | `PUT` | Cập nhật thông số quy tắc NAT |
| | `/api/v1/router/nat/:id` | `PATCH` | Bật/tắt trạng thái quy tắc NAT |
| | `/api/v1/router/nat/:id` | `DELETE` | Xóa quy tắc NAT |
| | `/api/v1/router/connections` | `GET` | Danh sách các phiên kết nối Conntrack hoạt động |
| | `/api/v1/router/connections/:id` | `DELETE` / `POST` | Đóng/ngắt tức thì (Kill) phiên kết nối nguy hại |
| **DNS & Lọc Nội Dung** | `/api/v1/dns/services` | `GET` | Danh sách 11 nhóm ứng dụng kiểm soát |
| | `/api/v1/dns/services` | `PATCH` / `POST` | Khóa/Mở khóa nhóm dịch vụ (Game, AI, DoH Bypass, Torrent...) |
| | `/api/v1/dns/stats` | `GET` | Thống kê số lượng truy vấn và tỷ lệ chặn của AdGuard Home |
| | `/api/v1/dns/rewrites` | `GET` | Danh sách bản ghi DNS Rewrite nội bộ |
| | `/api/v1/dns/rewrites` | `POST` | Thêm mới ánh xạ tên miền nội bộ |
| | `/api/v1/dns/rewrites/:id` | `DELETE` | Xóa bản ghi DNS Rewrite |
| | `/api/v1/dns/querylog` | `GET` | Nhật ký phân giải DNS (hỗ trợ lọc `ALL`, `BLOCKED`, `RESOLVED`) |
| **Viễn Trắc & Lockdown** | `/api/v1/telemetry/live` | `GET` | Đo lường viễn trắc thời gian thực (PPS, Mbps, Drops, Active Sessions) |
| | `/api/v1/telemetry/live` | `POST` | Cập nhật chỉ số viễn trắc từ KernelFW hoặc Stress tool |
| | `/api/v1/telemetry/lockdown` | `PATCH` / `POST` | Bật/tắt chế độ Khóa khẩn cấp toàn diện (Emergency Lockdown) |
| **Vault & Kiểm Toán** | `/api/v1/vault/backups` | `GET` | Danh sách các snapshot sao lưu hệ thống |
| | `/api/v1/vault/backups` | `POST` | Tạo snapshot sao lưu cụm mã hóa mới |
| | `/api/v1/vault/restore/:filename` | `POST` | Khôi phục cấu hình hệ thống từ snapshot chỉ định |
| | `/api/v1/audit/logs` | `GET` | Danh sách nhật ký kiểm toán hệ thống (Audit Trail) |
| | `/api/v1/audit/logs` | `POST` | Ghi nhận hành vi quản trị mới |
| **Sức Khỏe Đa Cụm** | `/api/v1/cluster/health` | `GET` | Tổng hợp trạng thái 4 tầng (KernelFW, RouterOS, AdGuard, API, Panel) |

---

## 3. Kết Quả Kiểm Thử Tự Động (Automated Test Suite)
- **Kịch bản test:** `Aegis-API/test-management.js` (`npm run test:management`)
- **Kết quả:**
  ```text
  [Test] Initializing Fastify instance for management routes validation...

  --- 1. Testing Firewall & Mitigation Endpoints ---
    ✓ PASS: GET /api/v1/firewall/modules returns 16 modules
    ✓ PASS: PATCH /api/v1/firewall/modules updates module mode
    ✓ PASS: POST /api/v1/firewall/bans adds an IP to ban list
    ✓ PASS: GET /api/v1/firewall/bans retrieves active bans
    ✓ PASS: DELETE /api/v1/firewall/bans unbans IP
    ✓ PASS: POST /api/v1/firewall/cidr adds CIDR rule
    ✓ PASS: DELETE /api/v1/firewall/cidr/:id removes CIDR rule

  --- 2. Testing Router & NAT Endpoints ---
    ✓ PASS: GET /api/v1/router/leases returns leases list
    ✓ PASS: GET /api/v1/router/pppoe returns presets
    ✓ PASS: POST /api/v1/router/nat adds NAT port forwarding rule
    ✓ PASS: PATCH /api/v1/router/nat toggles rule enabled state
    ✓ PASS: DELETE /api/v1/router/nat/:id deletes NAT rule

  --- 3. Testing DNS & Content Security Endpoints ---
    ✓ PASS: GET /api/v1/dns/services returns 11 categories
    ✓ PASS: PATCH /api/v1/dns/services toggles service blocked state
    ✓ PASS: POST /api/v1/dns/rewrites adds DNS rewrite
    ✓ PASS: DELETE /api/v1/dns/rewrites/:id removes DNS rewrite

  --- 4. Testing Telemetry & Lockdown Endpoints ---
    ✓ PASS: GET /api/v1/telemetry/live returns telemetry structure
    ✓ PASS: PATCH /api/v1/telemetry/lockdown toggles emergency lockdown

  --- 5. Testing Vault & Audit Trail Endpoints ---
    ✓ PASS: POST /api/v1/vault/backups creates new snapshot
    ✓ PASS: POST /api/v1/vault/restore/:filename restores snapshot
    ✓ PASS: GET /api/v1/audit/logs returns recorded audit items

  --- 6. Testing Cluster Health Endpoint ---
    ✓ PASS: GET /api/v1/cluster/health returns multi-node status

  --- 7. Testing Path Aliases without /v1 ---
    ✓ PASS: GET /api/firewall/modules works via direct alias
    ✓ PASS: GET /api/cluster/health works via direct alias

  ========================================
  Summary: 24 Passed, 0 Failed
  ========================================
  ```

---

## 4. Tài Liệu Hướng Dẫn & Tích Hợp
- Đã cập nhật file `/home/minhmcpc/Projects/Aegis-API/README.md` với đầy đủ danh mục API và ví dụ gọi lệnh.
- Sẵn sàng bàn giao cho `panel-engineer` để trỏ trực tiếp các Next.js API Routes tới `AEGIS_API_URL`.
