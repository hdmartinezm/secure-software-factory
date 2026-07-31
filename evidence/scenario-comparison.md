# EFEX Secure Software Factory - Scenario Comparison

## Executive Summary

This document demonstrates the effectiveness of the EFEX DevSecOps pipeline by comparing two scenarios:

| Scenario | Code State | Pipeline Result | Deployment |
|----------|------------|-----------------|------------|
| **RED** | Vulnerable code (`vulnerable/`) | **BLOCKED** | Prevented |
| **GREEN** | Remediated code (`remediated/`) | PASSED | Allowed |

## Repository Structure

```
secure-software-factory/
├── vulnerable/           # RED SCENARIO - Intentionally insecure
│   ├── app/
│   │   ├── main.py       # SQL injection, command injection, hardcoded secrets
│   │   └── requirements.txt  # Outdated dependencies with CVEs
│   └── infra/
│       └── main.tf       # S3 public, IAM wildcards, RDS unencrypted
│
├── remediated/           # GREEN SCENARIO - Security best practices
│   ├── app/
│   │   ├── main.py       # Parameterized queries, env vars, safe subprocess
│   │   └── requirements.txt  # Updated secure dependencies
│   └── infra/
│       └── main.tf       # Encrypted S3, least privilege IAM, private RDS
│
└── Dockerfile            # Secure container (non-root, multi-stage)
```

## Visual Comparison

```
RED SCENARIO (vulnerable/)                  GREEN SCENARIO (remediated/)
================================            ================================

[Secrets Detection]  -----> FAIL            [Secrets Detection]  -----> PASS
        |                                           |
        v                                           v
[SAST Analysis]      -----> FAIL            [SAST Analysis]      -----> PASS
        |                                           |
        v                                           v
[Dependency Scan]    -----> FAIL            [Dependency Scan]    -----> PASS
        |                                           |
        v                                           v
[IaC Security]       -----> FAIL            [IaC Security]       -----> PASS
        |                                           |
        v                                           v
[Container Security] -----> PASS            [Container Security] -----> PASS
        |                                           |
        v                                           v
[Security Gate]      -----> BLOCKED         [Security Gate]      -----> PASSED
        |                                           |
        X                                           v
   BUILD STOPPED                            [Build & Push]       -----> PASS
                                                    |
                                                    v
                                            [SBOM & Signing]     -----> PASS
                                                    |
                                                    v
                                            DEPLOYED SECURELY
```

## Pipeline URLs

| Scenario | Run ID | Status | Date | URL |
|----------|--------|--------|------|-----|
| **RED** | 30651059422 | FAILURE | 2026-07-31 | [View Run](https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422) |
| **GREEN** | 30596948341 | SUCCESS | 2026-07-31 | [View Run](https://github.com/hdmartinezm/secure-software-factory/actions/runs/30596948341) |

## Security Findings Comparison

### RED Scenario - Vulnerabilities Detected

| Gate | Tool | Findings | Status |
|------|------|----------|--------|
| Secrets | Gitleaks | 4 demo secrets (DATABASE_PASSWORD, JWT_SECRET, etc.) | FAILED |
| SAST | Semgrep | 13 vulnerabilities (SQL injection, command injection) | FAILED |
| SCA | Trivy | HIGH/CRITICAL CVEs (PyYAML, requests, urllib3) | FAILED |
| IaC | Checkov | 28 misconfigurations (S3 public, IAM wildcards) | FAILED |
| Container | Trivy | 0 (main Dockerfile is secure) | PASSED |

### GREEN Scenario - All Secure

| Gate | Tool | Findings | Status |
|------|------|----------|--------|
| Secrets | Gitleaks | 0 secrets | PASSED |
| SAST | Semgrep | 0 vulnerabilities | PASSED |
| SCA | Trivy | 0 HIGH/CRITICAL CVEs | PASSED |
| IaC | Checkov | All checks passed | PASSED |
| Container | Trivy | 0 vulnerabilities | PASSED |

## Vulnerabilities Detected and Remediated

| Category | Vulnerability ID | RED (Vulnerable) | GREEN (Remediated) | Fix Applied |
|----------|-----------------|------------------|-------------------|-------------|
| **Secrets** | EFEX-VULN-001 | Hardcoded DB password | Environment variables | `os.getenv()` |
| **Secrets** | EFEX-VULN-001 | API keys in code | Secrets manager | External config |
| **SAST** | EFEX-VULN-002 | SQL Injection | Parameterized queries | `cursor.execute(?, params)` |
| **SAST** | EFEX-VULN-003 | Command Injection | Safe subprocess | `subprocess.run([...])` |
| **SAST** | EFEX-VULN-004 | Insecure YAML | Safe loader | `yaml.safe_load()` |
| **SAST** | EFEX-VULN-005 | Sensitive data in logs | Masked logging | Redacted output |
| **SCA** | CVE-2020-14343 | PyYAML 5.3.1 | PyYAML 6.0.1 | Version update |
| **SCA** | CVE-2023-32681 | requests 2.25.1 | requests 2.31.0 | Version update |
| **IaC** | CKV_AWS_53-56 | S3 public access | Block public access | `block_public_*` |
| **IaC** | EFEX_AWS_001 | S3 no encryption | AES-256 + KMS | `server_side_encryption` |
| **IaC** | CKV_AWS_61 | IAM Action: "*" | Least privilege | Specific permissions |
| **IaC** | CKV_AWS_277 | SG open to 0.0.0.0/0 | Restricted CIDR | VPC-only access |
| **Container** | EFEX-SEC-004 | Running as root | Non-root user | `USER 1000:1000` |

## Regulatory Compliance Mapping

| Control | Regulation | RED | GREEN | Evidence |
|---------|------------|-----|-------|----------|
| Encryption at rest | CNBV Art. 316 Bis 17 | FAIL | PASS | S3/RDS encryption enabled |
| Access control | SOC 2 CC6.3 | FAIL | PASS | IAM least privilege |
| Secrets management | SOC 2 CC6.1 | FAIL | PASS | No hardcoded secrets |
| Vulnerability mgmt | CNBV Circular 4/2021 | FAIL | PASS | Dependency scanning |
| Audit trail | SOC 2 CC7.2 | N/A | PASS | SBOM generation |
| Container security | CIS Docker Benchmark | FAIL | PASS | Non-root, minimal image |

## Demo Secrets Pattern

The RED scenario uses obvious fake secrets that are intentionally detectable:

```python
# vulnerable/app/main.py
DATABASE_PASSWORD = "HARDCODED_SECRET_FOR_DEMO_efex2024"
SPEI_API_TOKEN = "DEMO_API_KEY_spei_tk_12345678"
JWT_SECRET_KEY = "DEMO_JWT_SECRET_super_insecure_key"
AWS_ACCESS_KEY = "AKIADEMO12345EXAMPLE"
AWS_SECRET_KEY = "DEMO_SECRET_wJalrXUtnFEMI_K7MDENG_bPxRfiCY"
```

Custom Gitleaks rules detect these patterns:
- `efex-demo-hardcoded-secret` - HARDCODED_SECRET_FOR_DEMO*
- `efex-demo-api-key` - DEMO_API_KEY_*
- `efex-demo-jwt-secret` - DEMO_JWT_SECRET_*
- `efex-demo-generic` - DEMO_SECRET_*
- `efex-demo-aws-key` - AKIADEMO*

## Key Takeaways

1. **Pipeline as Gatekeeper**: The security pipeline prevented vulnerable code from reaching production
2. **Shift-Left Security**: Issues caught early in CI/CD, before deployment
3. **Defense in Depth**: Multiple layers (4/5 gates) caught different vulnerability types
4. **Custom Policy Enforcement**: EFEX-specific rules for Mexican fintech context
5. **Developer Workflow**: Clear feedback loop with actionable remediation guidance
6. **Supply Chain Security**: SBOM and signing ensure artifact integrity
7. **Compliance Ready**: CNBV and SOC 2 controls automatically enforced

## Evidence Files

| File | Description |
|------|-------------|
| `red/pipeline-failure-report.md` | Detailed RED scenario analysis with all findings |
| `green/pipeline-success-report.md` | Detailed GREEN scenario analysis |
| GitHub Actions Runs | Full audit trail available in repository |

## Repository

https://github.com/hdmartinezm/secure-software-factory
