# NOTE: Pinned to 3.13 (NOT 3.14). SQLModel 0.0.22 + Pydantic 2 fail to
# build table models on Python 3.14 (PEP 649 deferred annotations break
# SQLModel's metaclass: "Field 'id' requires a type annotation"). The image
# still builds on 3.14 but crashes at runtime. Revisit when SQLModel ships
# 3.14 support. See CHANGELOG 0.7.1.
FROM python:3.13.14-slim

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

# Build-time import smoke test: fail the build if the app can't be imported
# (catches runtime-only breakage like the SQLModel/Python 3.14 incompatibility
# that a plain `pip install` would NOT surface). DATABASE_URL points at /tmp so
# no PVC is needed during build.
RUN DATABASE_URL="sqlite:////tmp/build-check.db" \
    CONFIG_PATH=/tmp/none.json IMPORT_LEGACY_CONFIG=false CF_API_TOKEN=build \
    python -c "import app.main; assert app.main.app.version; print('import OK', app.main.app.version)" \
    && rm -f /tmp/build-check.db

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
