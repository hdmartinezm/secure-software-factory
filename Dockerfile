# EFEX Transfer Service - VULNERABLE Dockerfile
# ==============================================
# Este Dockerfile contiene configuraciones INSEGURAS intencionales
# para demostrar el pipeline DevSecOps. NO usar en produccion.
#
# Vulnerabilidades incluidas:
# - EFEX-VULN-007: Running as root
# - EFEX-VULN-008: No pinned base image version (supply chain risk)
# - EFEX-VULN-009: Copying entire context (may include secrets)
# - EFEX-VULN-010: No HEALTHCHECK
# - EFEX-VULN-011: Installing unnecessary packages
# - EFEX-VULN-012: Using ADD instead of COPY (URL fetch risk)

# EFEX-VULN-008: No pinned version - vulnerable to supply chain attacks
# Detectado por: Trivy (DS001), Checkov (CKV_DOCKER_3)
# Riesgo: Image tag can be overwritten with malicious version
FROM python:3.9

# EFEX-VULN-011: Installing packages that increase attack surface
# Detectado por: Trivy, Hadolint
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    netcat \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# EFEX-VULN-012: Using ADD instead of COPY
# ADD can fetch from URLs and auto-extract archives (security risk)
ADD . /app

# EFEX-VULN-009: Copying entire context may include:
# - .git directory (commit history, credentials)
# - .env files with secrets
# - Private keys
# - Config files with passwords
COPY . .

# Install Python dependencies
# EFEX-VULN: pip install without --no-cache-dir leaves cache with potential sensitive data
RUN pip install -r vulnerable-app/requirements.txt

# Expose port
EXPOSE 8000

# EFEX-VULN-010: No HEALTHCHECK defined
# Detectado por: Trivy (DS026), Checkov (CKV_DOCKER_2)
# Riesgo: Container orchestrator can't determine if app is healthy

# EFEX-VULN-007: No USER directive = runs as root (UID 0)
# Detectado por: Trivy (DS002), Checkov (CKV_DOCKER_8)
# Regulacion: SOC 2 CC6.8 - Principle of least privilege
# Riesgo: Container escape, host compromise, lateral movement
#
# Missing:
# RUN useradd -r -u 1000 -g appgroup appuser
# USER appuser

# Environment variables with secrets (bad practice)
ENV DATABASE_URL="mysql://efex_admin:efex_pr0d_2024@db:3306/transfers"
ENV DEBUG="true"
ENV LOG_LEVEL="DEBUG"

# Run the application
# EFEX-VULN: Binding to 0.0.0.0 without proper network controls
CMD ["python", "-m", "uvicorn", "vulnerable-app.main:app", "--host", "0.0.0.0", "--port", "8000"]
