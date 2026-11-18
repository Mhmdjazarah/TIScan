FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TISCAN_HOST=0.0.0.0 \
    TISCAN_PORT=8787 \
    TISCAN_ALLOWED_HOSTS=localhost,127.0.0.1,::1 \
    TISCAN_DB=/app/data/tiscan.db \
    TISCAN_ENV_FILE=/app/data/settings.env \
    TISCAN_NO_BROWSER=1

WORKDIR /app
RUN useradd --create-home --uid 10001 tiscan

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY tiscan ./tiscan
COPY .env.example ./
RUN mkdir -p /app/data && chown -R tiscan:tiscan /app/data

USER tiscan
VOLUME ["/app/data"]
EXPOSE 8787

HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/stats', timeout=4)" || exit 1

CMD ["python", "-m", "tiscan", "serve", "--no-browser"]
