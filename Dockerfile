# Dockerfile
FROM python:slim

# Install runtime dep
RUN pip install --no-cache-dir requests

# Create non-root user
RUN useradd -u 10001 -r -s /usr/sbin/nologin appuser

# App directory
WORKDIR /app
COPY cloudflare-ddns.py /app/cloudflare-ddns.py

# Install dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
RUN rm -f /app/requirements.txt

# Default config path is /etc/config/records.json
RUN mkdir -p /etc/config && chown -R appuser:appuser /etc/config

USER appuser

ENV PYTHONUNBUFFERED=1
ENV CONFIG_PATH=/etc/config/records.json
ENV CF_API_URL=https://api.cloudflare.com/client/v4
ENV IP_POLL_INTERVAL_SECONDS=60
ENV CF_RESYNC_INTERVAL_SECONDS=3600
ENV REQUEST_TIMEOUT_SECONDS=10
ENV IPV4_ENDPOINT=https://v4.ifconfig.me/ip
ENV IPV6_ENDPOINT=https://v6.ifconfig.me/ip
ENV LOG_LEVEL=INFO
ENV DEFAULT_TTL=300
ENV DEFAULT_PROXIED=false

CMD ["python", "/app/cloudflare-ddns.py"]