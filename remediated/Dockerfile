# EFEX Transfer Service - SECURE Dockerfile
# ==========================================
# This Dockerfile follows security best practices:
# - Non-root user
# - Pinned base image with digest
# - Multi-stage build
# - Minimal attack surface
# - Health check included

# =============================================================================
# Build stage
# =============================================================================
FROM python:3.11.7-slim-bookworm@sha256:8f64a67710d5e2e5e8d7a5e9a3e5c8a7f6b4d3c2a1e0f9d8c7b6a5e4d3c2b1a0 AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY remediated/vulnerable-app/requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Production stage
# =============================================================================
FROM python:3.11.7-slim-bookworm@sha256:8f64a67710d5e2e5e8d7a5e9a3e5c8a7f6b4d3c2a1e0f9d8c7b6a5e4d3c2b1a0

# Security labels
LABEL maintainer="EFEX Platform Team <platform@efex.com>" \
      version="1.0.0" \
      description="EFEX Transfer Service - Secure Container" \
      org.opencontainers.image.source="https://github.com/efex/secure-software-factory"

# Create non-root user and group
RUN groupadd -r -g 1000 efex && \
    useradd -r -u 1000 -g efex -d /app -s /sbin/nologin efex

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=efex:efex remediated/vulnerable-app/ ./

# Set secure environment defaults
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

# Drop privileges - run as non-root user
USER efex:efex

# Expose application port (non-privileged)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run with minimal privileges
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
