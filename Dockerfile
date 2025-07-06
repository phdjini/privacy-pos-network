# Dockerfile
FROM python:3.9-slim

# 작업 디렉토리 설정
WORKDIR /app

# 시스템 패키지 업데이트 및 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Python 의존성 파일 복사
COPY requirements.txt .

# Python 패키지 설치
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드 복사
COPY . .

# 포트 노출
EXPOSE 30303 8080

# 데이터 저장을 위한 볼륨
VOLUME ["/app/data"]

# 환경 변수 설정
ENV PYTHONPATH=/app
ENV NODE_ENV=production

# 헬스체크 추가
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/status || exit 1

# 실행 명령
CMD ["python", "privacy_pos_network.py", "start", "--config", "/app/config/config.json"]