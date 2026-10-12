#!/usr/bin/env bash
# ==============================================================================
# AEGIS API - AUTO GIT SYNC & DOCKER AUTO-DEPLOY SCRIPT
# ==============================================================================

set -euo pipefail

APP_DIR="${APP_DIR:-/home/minhmcpc/aegis-api}"
LOG_FILE="$APP_DIR/auto-sync.log"

cd "$APP_DIR"

# Ensure SSH uses GitHub key
export GIT_SSH_COMMAND="ssh -i $HOME/.ssh/id_github_ed25519 -o StrictHostKeyChecking=accept-new"

# Check upstream origin main
git fetch origin main > /dev/null 2>&1 || exit 0

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" != "$REMOTE" ]; then
    echo "==================================================" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🚀 Phát hiện commit mới trên GitHub ($LOCAL -> $REMOTE)" >> "$LOG_FILE"
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 📥 Đang kéo code mới (git pull)..." >> "$LOG_FILE"
    git pull origin main >> "$LOG_FILE" 2>&1
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🐳 Đang build và restart container Docker..." >> "$LOG_FILE"
    docker compose up -d --build >> "$LOG_FILE" 2>&1
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] 🧹 Đang dọn dẹp docker images cũ..." >> "$LOG_FILE"
    docker image prune -f >> "$LOG_FILE" 2>&1
    
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✅ Đã cập nhật thành công lên commit mới!" >> "$LOG_FILE"
    echo "==================================================" >> "$LOG_FILE"
fi
