FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install deps first for layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# Create non-root user
RUN useradd -u 10001 -r -s /usr/sbin/nologin appuser

# App source
COPY app/   /app/app/
COPY core/  /app/core/

# Data dir for SQLite, writable by appuser
RUN mkdir -p /app/data /etc/config && chown -R appuser:appuser /app /etc/config

USER appuser

EXPOSE 8080

# Default configuration (override via env / k8s)
ENV CONFIG_PATH=/etc/config/records.json \
    DATABASE_URL=sqlite:////app/data/cloudflare-ddns.db \
    POLL_INTERVAL_SECONDS=60 \
    IPV4_ENDPOINT=https://ipinfo.io/ip \
    ENABLE_ANNOTATION_DISCOVERY=true \
    ENABLE_TRAEFIK_DISCOVERY=true \
    LOG_LEVEL=INFO

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
