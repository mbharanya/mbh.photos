# Minimal Python base
FROM python:3.12-slim

# Security / behavior defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# System deps: we install curl so it's easy (inside container) to refresh GeoLite,
# and libmaxminddb is needed for geoip2 to read .mmdb efficiently on some platforms.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libmaxminddb0 \
        curl && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
# - flask: web framework
# - gunicorn: prod WSGI server
# - geoip2: MaxMind GeoLite2 reader
RUN pip install --no-cache-dir \
    flask \
    gunicorn \
    geoip2

# Copy the application code
COPY app.py /app/app.py

# The service listens on 8000 internally
EXPOSE 8000

# Run with gunicorn in production mode
# - 2 workers is fine for a small box; tweak if you want
CMD ["gunicorn", "-b", "0.0.0.0:8000", "--workers", "2", "app:app"]
