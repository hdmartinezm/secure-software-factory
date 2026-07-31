# EFEX Secure Software Factory - RED Scenario Evidence

## Pipeline Run Details

| Field | Value |
|-------|-------|
| **Run ID** | 30651059422 |
| **Conclusion** | FAILURE |
| **Date** | 2026-07-31T17:24:45Z |
| **Branch** | main |
| **Commit** | `c862b4e` - fix(security): Adjust Gitleaks and Semgrep to detect demo secrets |
| **URL** | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422 |

## Security Checks Results

| Check | Status | Findings | Failure Reason |
|-------|--------|----------|----------------|
| 🔐 Secrets Detection | **FAILED** | 4 secrets | Demo secrets detected by Gitleaks |
| 🔍 SAST Analysis | **FAILED** | 13 vulns | SQL/Command injection, insecure deserialization |
| 📦 Dependency Scan (SCA) | **FAILED** | HIGH/CRITICAL CVEs | Vulnerable dependencies in requirements.txt |
| 🏗️ IaC Security Scan | **FAILED** | 28 issues | S3 public, IAM wildcards, RDS unencrypted |
| 🐳 Container Security | PASSED | 0 | Main Dockerfile is secure |
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

### 3. IaC Security (Checkov) - 28 Failed Checks

```
Passed checks: 19, Failed checks: 28, Skipped checks: 0

Critical Findings:
- CKV_AWS_41: Hard coded AWS access key in provider
- CKV_AWS_61: IAM policy allows assume role across all services
- CKV_AWS_60: IAM role allows any principal to assume it
- CKV_AWS_274: AdministratorAccess policy attached
- CKV_AWS_25: Security group allows 0.0.0.0/0 to port 3389
- CKV_AWS_277: Security group allows 0.0.0.0/0 to all ports
- CKV_AWS_93: S3 bucket policy lockout risk
- CKV_AWS_133: RDS instance missing backup policy
- CKV_AWS_354: RDS Performance Insights not encrypted with KMS
- CKV2_AWS_56: IAMFullAccess policy used
- CKV2_AWS_69: RDS not configured with encryption in transit
```

### 4. Dependency Scan (Trivy/SCA) - Vulnerable Dependencies

```
vulnerable/app/requirements.txt contains:
- PyYAML==5.3.1 (CVE-2020-14343 - CRITICAL)
- requests==2.25.1 (CVE-2023-32681 - HIGH)
- urllib3==1.26.5 (Multiple CVEs)
```

### 5. Security Gate

```
🚦 Security Gate: FAILED
Reason: One or more security checks did not pass

Failed checks:
- secrets-scan: FAILED
- sast: FAILED
- sca: FAILED
- iac-scan: FAILED
```

## Job URLs

| Job | Status | URL |
|-----|--------|-----|
| Secrets Detection | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422/job/91224124644 |
| SAST Analysis | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422/job/91224124650 |
| Dependency Scan | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422/job/91224124515 |
| IaC Security | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422/job/91224124748 |
| Container Security | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422/job/91224124568 |
| Security Gate | FAILED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422/job/91224731906 |

## Vulnerable Code Scanned

The pipeline scanned the intentionally vulnerable code in:
- `vulnerable/app/main.py` - Python API with security flaws
- `vulnerable/app/requirements.txt` - Outdated dependencies with CVEs
- `vulnerable/infra/main.tf` - Insecure Terraform configuration

## Conclusion

The pipeline correctly **BLOCKED** the vulnerable code from being deployed. This demonstrates:

1. **Defense in Depth** - 4 of 5 security layers caught different vulnerabilities
2. **Fail-Fast** - Pipeline stopped at Security Gate, preventing build/deploy
3. **Custom Policy Enforcement** - EFEX-specific Gitleaks and Semgrep rules triggered
4. **Compliance Controls** - CNBV/SOC2 requirements enforced via Checkov policies
5. **Comprehensive Coverage** - Secrets, SAST, SCA, and IaC all validated

### Security Gates Summary

| Gate | Tool | Findings | Blocked |
|------|------|----------|---------|
| Secrets | Gitleaks | 4 demo secrets | YES |
| SAST | Semgrep | 13 vulnerabilities | YES |
| SCA | Trivy | HIGH/CRITICAL CVEs | YES |
| IaC | Checkov | 28 misconfigurations | YES |
| Container | Trivy | 0 (secure Dockerfile) | NO |

**Total: 4/5 gates failed = Pipeline BLOCKED**
