#!/bin/bash

# deploy.sh - Privacy-PoS EC2 배포 스크립트

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 로그 함수
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 환경 변수 설정
GITHUB_REPO="your-username/privacy-pos-network"
PROJECT_DIR="/opt/privacy-pos"
CONFIG_DIR="$PROJECT_DIR/config"
DATA_DIR="/var/lib/privacy-pos"
LOG_DIR="/var/log/privacy-pos"

log_info "Starting Privacy-PoS deployment on EC2..."

# 1. 시스템 업데이트
log_info "Updating system packages..."
sudo apt-get update -y
sudo apt-get upgrade -y

# 2. Docker 설치
log_info "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    sudo systemctl enable docker
    sudo systemctl start docker
    log_info "Docker installed successfully"
else
    log_info "Docker already installed"
fi

# 3. Docker Compose 설치
log_info "Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    log_info "Docker Compose installed successfully"
else
    log_info "Docker Compose already installed"
fi

# 4. Git 설치
log_info "Installing Git..."
sudo apt-get install -y git

# 5. 필요한 디렉토리 생성
log_info "Creating directories..."
sudo mkdir -p $PROJECT_DIR
sudo mkdir -p $CONFIG_DIR
sudo mkdir -p $DATA_DIR
sudo mkdir -p $LOG_DIR
sudo chown -R $USER:$USER $PROJECT_DIR
sudo chown -R $USER:$USER $DATA_DIR
sudo chown -R $USER:$USER $LOG_DIR

# 6. 프로젝트 클론
log_info "Cloning project from GitHub..."
cd /opt
if [ -d "$PROJECT_DIR" ]; then
    cd $PROJECT_DIR
    git pull origin main
else
    git clone https://github.com/$GITHUB_REPO.git privacy-pos
    cd $PROJECT_DIR
fi

# 7. 설정 파일 생성
log_info "Creating configuration files..."

# config.json 생성
cat > $CONFIG_DIR/config.json << 'EOF'
{
  "network": {
    "port": 30303,
    "max_peers": 50,
    "heartbeat_interval": 30,
    "sync_timeout": 120
  },
  "consensus": {
    "block_period": 3,
    "epoch_length": 30000,
    "privacy_threshold": 67,
    "max_validators": 21,
    "min_validators": 3
  },
  "privacy": {
    "risk_threshold": 80,
    "consensus_timeout": 30,
    "validation_cache_size": 1000
  },
  "database": {
    "type": "sqlite",
    "path": "/app/data/privacy_pos.db"
  },
  "api": {
    "enabled": true,
    "port": 8080,
    "cors_enabled": true
  },
  "logging": {
    "level": "INFO",
    "file": "/var/log/privacy-pos/node.log"
  }
}
EOF

# 8. Nginx 설정 생성
log_info "Creating Nginx configuration..."
mkdir -p nginx
cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream privacy_pos_api {
        server privacy-pos-bootstrap:8080;
        server privacy-pos-validator1:8080;
        server privacy-pos-validator2:8080;
    }

    upstream privacy_pos_network {
        server privacy-pos-bootstrap:30303;
        server privacy-pos-validator1:30304;
        server privacy-pos-validator2:30305;
    }

    server {
        listen 80;
        server_name _;

        # API 프록시
        location /api/ {
            proxy_pass http://privacy_pos_api/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # WebSocket 지원
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }

        # 헬스체크
        location /health {
            proxy_pass http://privacy_pos_api/status;
        }

        # 정적 파일 (필요시)
        location / {
            return 200 'Privacy-PoS Network is running';
            add_header Content-Type text/plain;
        }
    }
}
EOF

# 9. 모니터링 스크립트 생성
log_info "Creating monitoring scripts..."
mkdir -p monitoring
cat > monitoring/monitor.py << 'EOF'
#!/usr/bin/env python3
import asyncio
import aiohttp
import json
import time
from datetime import datetime

class NetworkMonitor:
    def __init__(self, nodes):
        self.nodes = nodes

    async def check_node_health(self, session, node_url):
        try:
            async with session.get(f"http://{node_url}/status", timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "url": node_url,
                        "status": "healthy",
                        "data": data,
                        "timestamp": datetime.now().isoformat()
                    }
        except Exception as e:
            return {
                "url": node_url,
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    async def monitor_loop(self):
        async with aiohttp.ClientSession() as session:
            while True:
                print(f"\n{'='*50}")
                print(f"Network Health Check - {datetime.now()}")
                print(f"{'='*50}")

                tasks = []
                for node in self.nodes:
                    tasks.append(self.check_node_health(session, node))

                results = await asyncio.gather(*tasks)

                healthy_nodes = 0
                for result in results:
                    status_icon = "✅" if result["status"] == "healthy" else "❌"
                    print(f"{status_icon} {result['url']}: {result['status']}")

                    if result["status"] == "healthy":
                        healthy_nodes += 1
                        data = result["data"]
                        print(f"   Block: {data.get('current_block', 'N/A')}")
                        print(f"   Peers: {data.get('connected_peers', 'N/A')}")
                        print(f"   Pending TXs: {data.get('pending_transactions', 'N/A')}")

                print(f"\nNetwork Health: {healthy_nodes}/{len(self.nodes)} nodes healthy")
                await asyncio.sleep(30)

if __name__ == "__main__":
    import os

    nodes = os.getenv("MONITOR_NODES", "localhost:8080").split(",")
    monitor = NetworkMonitor(nodes)

    try:
        asyncio.run(monitor.monitor_loop())
    except KeyboardInterrupt:
        print("\nMonitoring stopped")
EOF

# 10. 시스템 서비스 생성
log_info "Creating systemd service..."
sudo tee /etc/systemd/system/privacy-pos.service > /dev/null << EOF
[Unit]
Description=Privacy-PoS Blockchain Network
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

# 11. 방화벽 설정
log_info "Configuring firewall..."
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 30303:30310/tcp  # P2P 네트워크
sudo ufw allow 8080:8090/tcp    # API 포트
sudo ufw --force enable

# 12. Docker 이미지 빌드
log_info "Building Docker images..."
docker-compose build

# 13. 네트워크 시작
log_info "Starting Privacy-PoS network..."
docker-compose up -d

# 14. 서비스 등록
log_info "Enabling systemd service..."
sudo systemctl daemon-reload
sudo systemctl enable privacy-pos.service

# 15. 상태 확인
log_info "Checking deployment status..."
sleep 30

echo
log_info "Deployment completed! Checking services..."
docker-compose ps

echo
log_info "Network endpoints:"
echo "  - Bootstrap Node API: http://$(curl -s ifconfig.me):8080"
echo "  - Validator 1 API: http://$(curl -s ifconfig.me):8081"
echo "  - Validator 2 API: http://$(curl -s ifconfig.me):8082"
echo "  - Load Balancer: http://$(curl -s ifconfig.me):80"

echo
log_info "Useful commands:"
echo "  - Check logs: docker-compose logs -f"
echo "  - Restart network: docker-compose restart"
echo "  - Stop network: docker-compose down"
echo "  - Update code: git pull && docker-compose build && docker-compose up -d"

echo
log_info "Testing network connectivity..."
for port in 8080 8081 8082; do
    if curl -s "http://localhost:$port/status" > /dev/null; then
        log_info "✅ Port $port: OK"
    else
        log_error "❌ Port $port: Failed"
    fi
done

log_info "Privacy-PoS network deployment completed successfully! 🚀"