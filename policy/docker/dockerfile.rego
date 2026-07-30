# EFEX Custom Policy: Dockerfile Security
# ========================================
# Policy ID: EFEX-DOCKER-*
# Regulatory Mapping: SOC 2 CC6.8, CIS Docker Benchmark
#
# These policies enforce container security best practices.
# Used with conftest to validate Dockerfiles.

package docker

import future.keywords.in

# =============================================================================
# EFEX-DOCKER-001: Containers must not run as root
# Severity: CRITICAL
# Regulation: SOC 2 CC6.8 - Principle of least privilege
# =============================================================================
deny[msg] {
    input.user == ""
    msg := "EFEX-DOCKER-001: Dockerfile must specify a non-root USER. Add 'RUN useradd -r appuser && USER appuser' before CMD. Regulation: SOC 2 CC6.8"
}

deny[msg] {
    input.user == "root"
    msg := "EFEX-DOCKER-001: Dockerfile explicitly sets USER to root. Use a non-privileged user (UID >= 1000)."
}

deny[msg] {
    input.user == "0"
    msg := "EFEX-DOCKER-001: Dockerfile sets USER to UID 0 (root). Use a non-privileged user."
}

# =============================================================================
# EFEX-DOCKER-002: Base images must be pinned to specific versions
# Severity: HIGH
# Regulation: Supply chain security
# =============================================================================
deny[msg] {
    input.from[i].image
    image := input.from[i].image
    not contains(image, ":")
    not contains(image, "@sha256:")
    msg := sprintf("EFEX-DOCKER-002: Base image '%s' must be pinned to a specific version or digest. Use 'image:version' or 'image@sha256:...'", [image])
}

deny[msg] {
    input.from[i].image
    image := input.from[i].image
    endswith(image, ":latest")
    msg := sprintf("EFEX-DOCKER-002: Base image '%s' uses 'latest' tag. Pin to a specific version for reproducibility.", [image])
}

# =============================================================================
# EFEX-DOCKER-003: HEALTHCHECK must be defined
# Severity: MEDIUM
# Regulation: SOC 2 CC7.1 - Availability monitoring
# =============================================================================
warn[msg] {
    not input.healthcheck
    msg := "EFEX-DOCKER-003: Dockerfile should include HEALTHCHECK instruction for container health monitoring."
}

# =============================================================================
# EFEX-DOCKER-004: Avoid using ADD for remote URLs
# Severity: MEDIUM
# Regulation: Supply chain security
# =============================================================================
deny[msg] {
    input.add[i].src
    src := input.add[i].src
    startswith(src, "http://")
    msg := sprintf("EFEX-DOCKER-004: ADD instruction fetches from HTTP URL '%s'. Use HTTPS or COPY with verified files.", [src])
}

warn[msg] {
    input.add[i].src
    src := input.add[i].src
    startswith(src, "https://")
    msg := sprintf("EFEX-DOCKER-004: ADD instruction fetches from URL '%s'. Consider using COPY with pre-downloaded verified files.", [src])
}

# =============================================================================
# EFEX-DOCKER-005: Avoid installing unnecessary packages
# Severity: LOW
# Regulation: Attack surface reduction
# =============================================================================
dangerous_packages := {
    "curl",
    "wget",
    "netcat",
    "nc",
    "nmap",
    "telnet",
    "ssh",
    "vim",
    "nano",
}

warn[msg] {
    input.run[i].cmd
    cmd := input.run[i].cmd
    contains(cmd, "apt-get install")
    pkg := dangerous_packages[_]
    contains(cmd, pkg)
    msg := sprintf("EFEX-DOCKER-005: Installing '%s' increases attack surface. Remove if not required for runtime.", [pkg])
}

warn[msg] {
    input.run[i].cmd
    cmd := input.run[i].cmd
    contains(cmd, "apk add")
    pkg := dangerous_packages[_]
    contains(cmd, pkg)
    msg := sprintf("EFEX-DOCKER-005: Installing '%s' increases attack surface. Remove if not required for runtime.", [pkg])
}

# =============================================================================
# EFEX-DOCKER-006: Do not expose privileged ports
# Severity: MEDIUM
# =============================================================================
privileged_ports := {
    "22",   # SSH
    "23",   # Telnet
    "80",   # HTTP (use reverse proxy)
    "443",  # HTTPS (use reverse proxy)
}

warn[msg] {
    input.expose[i].port
    port := input.expose[i].port
    port_str := sprintf("%d", [port])
    port_str in privileged_ports
    msg := sprintf("EFEX-DOCKER-006: Exposing privileged port %s. Consider using higher ports (>1024) with reverse proxy.", [port_str])
}

# =============================================================================
# EFEX-DOCKER-007: Secrets should not be in ENV or ARG
# Severity: CRITICAL
# Regulation: SOC 2 CC6.1 - Secrets management
# =============================================================================
secret_keywords := {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "token",
    "credential",
    "private_key",
}

deny[msg] {
    input.env[i][0]
    env_name := lower(input.env[i][0])
    keyword := secret_keywords[_]
    contains(env_name, keyword)
    msg := sprintf("EFEX-DOCKER-007: ENV variable '%s' appears to contain secrets. Use runtime secrets injection instead.", [input.env[i][0]])
}

deny[msg] {
    input.arg[i]
    arg_name := lower(input.arg[i])
    keyword := secret_keywords[_]
    contains(arg_name, keyword)
    msg := sprintf("EFEX-DOCKER-007: ARG '%s' appears to contain secrets. Secrets in build args are visible in image history.", [input.arg[i]])
}

# =============================================================================
# EFEX-DOCKER-008: Use COPY instead of ADD when possible
# Severity: LOW
# =============================================================================
warn[msg] {
    input.add[i].src
    src := input.add[i].src
    not startswith(src, "http")
    not endswith(src, ".tar")
    not endswith(src, ".tar.gz")
    not endswith(src, ".tgz")
    msg := sprintf("EFEX-DOCKER-008: Use COPY instead of ADD for local file '%s' (ADD has implicit extraction behavior).", [src])
}
