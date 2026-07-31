# EFEX Transfer Service - VULNERABLE Dockerfile (DEMO)
# =====================================================
# This Dockerfile contains INTENTIONAL security issues for demonstration.
# DO NOT USE IN PRODUCTION.
#
# Vulnerabilities:
# - EFEX-VULN-007: Running as root (no USER directive)
# - EFEX-VULN-008: Unpinned base image
# - EFEX-VULN-009: Unnecessary packages installed
# - EFEX-VULN-010: No HEALTHCHECK
# - EFEX-VULN-011: ADD instead of COPY for local files

# VULNERABLE: Unpinned base image tag
FROM python:3.9

# VULNERABLE: Installing unnecessary packages (attack surface)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat-openbsd \
    vim \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# VULNERABLE: Using ADD instead of COPY for local files
ADD app/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# VULNERABLE: Copying entire context including potential secrets
ADD app/ .

# VULNERABLE: Exposing debug port
EXPOSE 8000
EXPOSE 5678

# VULNERABLE: No HEALTHCHECK directive

# VULNERABLE: Running as root (no USER directive)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
