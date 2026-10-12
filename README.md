# Aegis GeoIP API

API dịch vụ tra cứu thông tin IP tốc độ cao từ cơ sở dữ liệu MaxMind GeoLite2 (`GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb`, `GeoLite2-Country.mmdb`) với tính năng **tự động đồng bộ và cập nhật (Auto-Sync & Hot-Reload)** trực tiếp từ [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb/releases/latest).

---

## ⚡ Tính năng nổi bật

- 🚀 **Hiệu năng cực cao**: Viết bằng **Fastify** & thư viện `maxmind`, load toàn bộ dữ liệu MMDB vào bộ nhớ RAM, response time < 1ms.
- 🔄 **Auto-Sync & Zero-Downtime Hot-Reload**:
  - Tự động kiểm tra bản cập nhật mới nhất từ GitHub Releases qua cron job định kỳ (mặc định mỗi 12 tiếng).
  - Tự động tải về khi khởi động nếu chưa có dữ liệu.
  - Cơ chế **Atomic Swap**: Kiểm tra tính toàn vẹn của file trước khi ghi đè, hot-reload dữ liệu trực tiếp trong RAM mà không cần restart server hay gián đoạn request.
- 🛡️ **Bảo mật**:
  - Hỗ trợ endpoint trigger sync thủ công `POST /sync` bảo vệ bằng API Key.
  - Chuẩn hoá và validate định dạng IPv4 / IPv6.
- 🌐 **Hỗ trợ Reverse Proxy**: Nhận diện IP thực của client thông qua các header `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`.

---

## 🛠️ Cài đặt & Khởi chạy

### 1. Cài đặt dependencies

```bash
npm install
```

### 2. Cấu hình biến môi trường (`.env`)

Tạo file `.env` từ file mẫu:
```bash
cp .env.example .env
```

Nội dung `.env`:
```env
PORT=3000
HOST=0.0.0.0
DATA_DIR=./data

# Lịch cron kiểm tra cập nhật (mặc định mỗi 12 tiếng)
SYNC_CRON=0 */12 * * *
SYNC_ON_STARTUP=true

# Secret Key để gọi API POST /sync
SYNC_API_KEY=aegis-secret-sync-key

# (Tuỳ chọn) Token GitHub nếu cần tăng giới hạn rate limit
GITHUB_TOKEN=
```

### 3. Chạy Server

- Chế độ Production:
```bash
npm start
```

- Chế độ Development (tự reload khi sửa code):
```bash
npm run dev
```

### 4. Sử dụng Aegis Interactive CLI Agent

Aegis tích hợp giao diện dòng lệnh tương tác như Agent Console:

- **Chế độ tương tác REPL**:
  ```bash
  npm run cli
  ```
  *(Hoặc chạy trực tiếp `./src/cli.js`)*

  Trong giao diện `aegis ❯`, bạn có thể gõ trực tiếp IP (ví dụ `1.1.1.1`, `8.8.8.8`) hoặc các lệnh:
  - `<ip>`: Phân tích IP toàn diện với giao diện trực quan.
  - `threat <ip>`: Báo cáo bảo mật chi tiết (VPN, Proxy, Tor, Relay, Hosting).
  - `raw <ip>`: Xuất định dạng JSON IPInfo Enterprise chuẩn `forms.txt`.
  - `status`: Kiểm tra trạng thái RAM, Cron và các file MMDB.
  - `sync [--force]`: Đồng bộ cập nhật cơ sở dữ liệu mới nhất.
  - `keys`: Kiểm tra trạng thái các API key đã cấu hình trong `.env`.
  - `help` / `clear` / `exit`.

- **Chế độ chạy lệnh trực tiếp (One-shot CLI)**:
  ```bash
  node src/cli.js 1.1.1.1
  node src/cli.js threat 8.8.8.8
  node src/cli.js status
  ```

*Lưu ý: Trong lần khởi động đầu tiên, server/CLI sẽ tự động tải các file MMDB về thư mục `data/` trong vòng vài giây.*

---

## 📡 Danh sách API Endpoints

### 1. Tra cứu chuẩn hóa theo forms.txt (`GET /info/:ip`)

Endpoint trả về định dạng chuẩn hóa toàn diện (bao gồm hostname, geolocation, ASN, và phân tích proxy/vpn/anycast/hosting):

```bash
# Tra cứu chuẩn hóa (offline-first, siêu nhanh < 1ms)
curl http://localhost:3000/info/1.1.1.1

# Hoặc bật cờ ?enrich=true để kích hoạt kiểm tra chuyên sâu Proxy/VPN qua API
curl "http://localhost:3000/info/1.1.1.1?enrich=true"
```

---

### 2. Tra cứu theo từng loại (`type`) cho IP cụ thể

```bash
curl https://<domain>/{type}/{ip}
```

Các `type` được hỗ trợ:
- `asn`: Tra cứu thông tin mạng, Autonomous System Number và Organization.
- `city`: Tra cứu chi tiết Thành phố, Quốc gia, Toạ độ (lat/lon), Timezone, Postal code.
- `country`: Tra cứu Quốc gia, Mã ISO, Châu lục.
- `all`: Tổng hợp toàn bộ dữ liệu từ ASN, City và Country vào 1 response duy nhất.

#### Ví dụ:

**Tra cứu ASN:**
```bash
curl http://localhost:3000/asn/8.8.8.8
```
*Response:*
```json
{
  "success": true,
  "ip": "8.8.8.8",
  "type": "asn",
  "found": true,
  "data": {
    "autonomous_system_number": 15169,
    "autonomous_system_organization": "Google LLC"
  }
}
```

**Tra cứu City:**
```bash
curl http://localhost:3000/city/8.8.8.8
```
*Response:*
```json
{
  "success": true,
  "ip": "8.8.8.8",
  "type": "city",
  "found": true,
  "data": {
    "continent": { "code": "NA", "names": { "en": "North America" } },
    "country": { "iso_code": "US", "names": { "en": "United States" } },
    "location": {
      "latitude": 37.751,
      "longitude": -97.822,
      "time_zone": "America/Chicago"
    }
  }
}
```

**Tra cứu Country:**
```bash
curl http://localhost:3000/country/8.8.8.8
```

**Tra cứu tổng hợp (`all`):**
```bash
curl http://localhost:3000/all/8.8.8.8
```

---

### 2. Tra cứu IP của chính Client gọi API

Nếu không truyền IP, hệ thống sẽ tự động lấy IP của client đang request:

```bash
# Lấy toàn bộ thông tin của bạn
curl http://localhost:3000/me

# Hoặc lấy từng loại
curl http://localhost:3000/city
curl http://localhost:3000/asn
curl http://localhost:3000/country
```

---

### 3. Kiểm tra trạng thái hệ thống (`/status` & `/health`)

```bash
curl http://localhost:3000/status
```

*Response trả về tình trạng các file MMDB và lịch sync:*
```json
{
  "success": true,
  "uptime": 120.5,
  "databases": {
    "asn": { "loaded": true, "file": "GeoLite2-ASN.mmdb", "size": 8983422, "lastModified": "..." },
    "city": { "loaded": true, "file": "GeoLite2-City.mmdb", "size": 50789481, "lastModified": "..." },
    "country": { "loaded": true, "file": "GeoLite2-Country.mmdb", "size": 3410978, "lastModified": "..." }
  },
  "sync": {
    "isSyncing": false,
    "lastSyncTime": "2026-10-12T05:59:29.520Z",
    "currentReleaseTag": "2026.10.10",
    "cronSchedule": "0 */12 * * *"
  }
}
```

---

### 4. Trigger đồng bộ thủ công (`POST /sync`)

Yêu cầu cung cấp header `X-Sync-Key` hoặc `Authorization: Bearer <key>`:

```bash
# Kiểm tra và tải nếu có bản cập nhật mới
curl -X POST http://localhost:3000/sync \
  -H "X-Sync-Key: aegis-secret-sync-key"

# Bắt buộc tải lại (Force download)
curl -X POST "http://localhost:3000/sync?force=true" \
  -H "X-Sync-Key: aegis-secret-sync-key"
```

---

## 🚀 Hướng dẫn Triển khai (Deploy Production)

### Cách 1: Triển khai bằng Docker & Docker Compose (Khuyên dùng)

Đây là cách nhanh nhất và an toàn nhất, tự động cách ly môi trường và mount volume lưu trữ dữ liệu MMDB:

```bash
# 1. Clone repository và chuẩn bị .env
cp .env.example .env
nano .env # Điền các API key của bạn

# 2. Khởi chạy với Docker Compose
npm run docker:up
# hoặc: docker compose up -d --build

# 3. Xem log kiểm tra
npm run docker:logs

# 4. Dừng container khi cần
npm run docker:down
```

Dữ liệu MMDB sẽ được tự động lưu bền vững trong thư mục `./data` trên máy chủ chủ (host).

---

### Cách 2: Triển khai trên Linux VPS với PM2 & Nginx

Nếu bạn deploy trực tiếp trên Ubuntu/Debian server:

#### 1. Cài đặt Node.js & PM2
```bash
sudo apt update
sudo apt install -y curl git
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
sudo npm install -g pm2
```

#### 2. Khởi chạy ứng dụng với PM2
```bash
# Clone & cài đặt thư viện
npm ci --omit=dev

# Khởi chạy qua ecosystem file đã cấu hình sẵn
npm run pm2:start

# Thiết lập tự động khởi động cùng hệ thống khi reboot
pm2 startup
pm2 save

# Quản lý logs & tiến trình
npm run pm2:logs
pm2 monit
```

#### 3. Cấu hình Nginx Reverse Proxy & SSL (HTTPS)
Sao chép cấu hình mẫu từ `deploy/nginx.conf`:
```bash
sudo cp deploy/nginx.conf /etc/nginx/sites-available/aegis-api.conf
sudo ln -s /etc/nginx/sites-available/aegis-api.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Cài đặt SSL miễn phí qua Certbot Let's Encrypt
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d api.yourdomain.com
```

---

## 📂 Cấu trúc thư mục

```
Aegis-API/
├── Dockerfile               # Production Docker image (Node.js Alpine)
├── docker-compose.yml       # Docker Compose service & volume configuration
├── ecosystem.config.cjs     # PM2 configuration cho production VPS
├── deploy/
│   └── nginx.conf           # Mẫu Nginx reverse proxy & SSL config
├── data/                    # Thư mục lưu trữ database MMDB & metadata
├── src/
│   ├── config.js            # Nạp và quản trị biến môi trường .env
│   ├── cli.js               # Interactive CLI Agent Console (aegis)
│   ├── routes/              # Fastify route handlers
│   ├── services/            # MMDB, Threat, RDAP, Domains, Sync services
│   ├── utils/               # TTL MemoryCache
│   └── server.js            # Fastify server entry point
├── .env.example             # Mẫu template biến môi trường
├── package.json             # Scripts & dependencies
└── README.md
```
