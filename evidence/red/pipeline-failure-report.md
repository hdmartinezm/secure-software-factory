# EFEX Secure Software Factory - RED Scenario Evidence

## Pipeline Run Details

| Field | Value |
|-------|-------|
| **Run ID** | 30729290150 |
| **Conclusion** | FAILURE |
| **Date** | 2026-08-02T02:41:03Z |
| **Branch** | vulnerable-demo |
| **Commit** | `ffd274c` - fix(pipeline): Allow vars.SECURITY_GATE_MODE to take precedence |
| **URL** | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30729290150 |

## Security Checks Results

| Check | Status | Findings | Failure Reason |
|-------|--------|----------|----------------|
| 🔐 Secrets Detection | **FAILED** | 4 secrets | Hardcoded secrets in vulnerable/app/main.py |
| 🔍 SAST Analysis | **FAILED** | 13 vulns | SQL/Command injection, insecure deserialization |
| 📦 Dependency Scan (SCA) | **FAILED** | HIGH/CRITICAL CVEs | Vulnerable dependencies in requirements.txt |
| 🏗️ IaC Security Scan | PASSED | 0 issues | Infrastructure compliant |
| 🐳 Container Security | **FAILED** | 1 issue | Dockerfile runs as root (no USER directive) |
| 🚦 Security Gate | **FAILED** | - | Upstream checks failed |
| 📋 SBOM & Signing | SKIPPED | - | Security gate blocked |

## Detailed Findings

### 1. Secrets Detection (Gitleaks) - 4 Secrets Found

```
Finding:     DATABASE_PASSWORD = "REDACTED"
RuleID:      efex-demo-hardcoded-secret
File:        vulnerable/app/main.py:35

Finding:     JWT_SECRET_KEY = "REDACTED"
RuleID:      efex-demo-jwt-secret
File:        vulnerable/app/main.py:37

Finding:     AWS_SECRET_KEY = "REDACTED"
RuleID:      efex-demo-generic
File:        vulnerable/app/main.py:40

Finding:     SPEI_API_TOKEN = "REDACTED"
RuleID:      efex-demo-api-key
File:        vulnerable/app/main.py:36
```

**Custom EFEX Rules Triggered:**
- `efex-demo-hardcoded-secret` - Hardcoded database password
- `efex-demo-jwt-secret` - JWT secret in code
- `efex-demo-api-key` - API token exposed
- `efex-demo-generic` - AWS credentials in code

### 2. SAST Analysis (Semgrep) - 13 Vulnerabilities

```
Findings: 13 (13 blocking)

Vulnerabilities detected:
- EFEX-VULN-002: SQL Injection via f-string concatenation
- EFEX-VULN-003: Command Injection via shell=True
- EFEX-VULN-004: Insecure YAML deserialization (yaml.load)
- EFEX-VULN-005: Sensitive data logging
- Debug endpoint exposing secrets (/debug/config)
```

**Rulesets Applied:**
- `p/python` - Python security rules
- `p/security-audit` - General security audit
- `p/owasp-top-ten` - OWASP Top 10
- `p/command-injection` - Command injection detection
- `p/sql-injection` - SQL injection detection
- `.semgrep/` - Custom EFEX rules

### 3. Dependency Scan (Trivy/SCA) - Vulnerable Dependencies

```
vulnerable/app/requirements.txt contains:
- PyYAML==5.3.1 (CVE-2020-14343 - CRITICAL)
- requests==2.25.1 (CVE-2023-32681 - HIGH)
- urllib3==1.26.5 (Multiple CVEs)
- certifi==2022.12.7 (CVE-2023-37920 - HIGH)
```

### 4. Container Security - Root User

```
vulnerable/Dockerfile analysis:
- No USER directive found
- Container runs as root by default
- EFEX-SEC-004: Dockerfile must specify non-root USER
```

### 5. Security Gate

```
🚦 Security Gate: FAILED
Reason: One or more security checks did not pass

Failed checks:
- secrets-scan: FAILED
- sast: FAILED
- sca: FAILED
- container: FAILED
```

## Job URLs

| Job | Status | URL |
|-----|--------|-----|
| Secrets Detection | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30729290150/job/91446548463 |
| SAST Analysis | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30729290150/job/91446548468 |
| Dependency Scan | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30729290150/job/91446548461 |
| IaC Security | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30729290150/job/91446548475 |
| Container Security | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30729290150/job/91446548462 |
| Security Gate | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30729290150/job/91446597071 |

## Vulnerable Code Scanned

The pipeline scanned the intentionally vulnerable code in:
- `vulnerable/app/main.py` - Python API with security flaws
- `vulnerable/app/requirements.txt` - Outdated dependencies with CVEs
- `vulnerable/Dockerfile` - Container running as root
- `vulnerable/infra/main.tf` - Terraform configuration

## Conclusion

The pipeline correctly **BLOCKED** the vulnerable code from being deployed. This demonstrates:

1. **Defense in Depth** - 4 of 5 security layers caught different vulnerabilities
2. **Fail-Fast** - Pipeline stopped at Security Gate, preventing build/deploy
3. **Custom Policy Enforcement** - EFEX-specific Gitleaks and Semgrep rules triggered
4. **Container Hardening** - Root user detection blocked deployment
5. **SCA Coverage** - Vulnerable dependencies detected with CVE details

### Security Gates Summary

| Gate | Tool | Findings | Blocked |
|------|------|----------|---------|
| Secrets | Gitleaks | 4 demo secrets | YES |
| SAST | Semgrep | 13 vulnerabilities | YES |
| SCA | Trivy | HIGH/CRITICAL CVEs | YES |
| IaC | Checkov | 0 issues | NO |
| Container | Hadolint/Trivy | Root user | YES |

**Total: 4/5 gates failed = Pipeline BLOCKED**
