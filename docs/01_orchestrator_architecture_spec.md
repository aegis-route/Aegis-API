# Đặc Tả Kiến Trúc Quản Trị Hệ Thống Aegis Suite (Low-Tech / Zero-Setup)

## Mục tiêu
Tích hợp toàn diện các phân hệ quản lý dữ liệu vào `Aegis-API` và liên kết trực tiếp với `Aegis-Panel`, đáp ứng tiêu chí **Low-Tech / Zero-Config**:
1. **Lưu trữ đơn giản (Zero Database Setup):** Lưu trữ toàn bộ trạng thái vào các file JSON con người đọc hiểu được tại `Aegis-API/data/store/`.
2. **Khởi tạo tự động (Self-Healing / Auto-Init):** Nếu file JSON chưa tồn tại, tự động sinh dữ liệu cấu hình chuẩn ban đầu (Initial Presets).
3. **Hot-Sync thời gian thực:** Mọi thay đổi từ giao diện Aegis-Panel được ghi ngay vào file JSON và có thể sửa tay trực tiếp bằng text editor.
4. **API Restful chuẩn hóa:**
   - `/api/v1/firewall/*`: Modules (16 mitigation), Auto-bans, CIDR Rules.
   - `/api/v1/router/*`: DHCP Leases, FastTrack, NAT Rules, PPPoE Profiles, Conntrack Sessions.
   - `/api/v1/dns/*`: Blocked Services, DNS Rewrites, DNS Stats, Query Logs.
   - `/api/v1/telemetry/*`: Live metrics (PPS, Mbps, Drops, Lockdown status).
   - `/api/v1/vault/*`: Backup Snapshots, Restore Snapshot.
   - `/api/v1/audit/*`: Audit Trail Logs.
   - `/api/v1/cluster/health`: Tổng hợp sức khỏe đa tầng.

## Phân công trách nhiệm
- **`api-engineer`**: Xây dựng `Aegis-API/src/services/store.service.js` và các routes Fastify tương ứng, đăng ký vào `server.js`.
- **`panel-engineer`**: Cập nhật adapter và route handlers của `Aegis-Panel` để trỏ tới `AEGIS_API_URL`.
- **`qa-tester`**: Kiểm thử đối chuẩn schema và xác thực luồng đồng bộ hai chiều.
