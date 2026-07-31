# EFEX Secure Software Factory - Scenario Comparison

## Executive Summary

This document demonstrates the effectiveness of the EFEX DevSecOps pipeline by comparing two scenarios:

| Scenario | Code State | Pipeline Result | Deployment |
|----------|------------|-----------------|------------|
| **RED** | Vulnerable code | BLOCKED | Prevented |
| **GREEN** | Remediated code | PASSED | Allowed |

## Visual Comparison

```
RED SCENARIO (Vulnerable Code)                  GREEN SCENARIO (Remediated Code)
================================                ================================

[Secrets Detection]  -----> FAIL               [Secrets Detection]  -----> PASS
        |                                              |
        v                                              v
[SAST Analysis]      -----> PASS               [SAST Analysis]      -----> PASS
        |                                              |
        v                                              v
[Dependency Scan]    -----> FAIL               [Dependency Scan]    -----> PASS
        |                                              |
        v                                              v
[IaC Security]       -----> FAIL               [IaC Security]       -----> PASS
        |                                              |
        v                                              v
[Container Security] -----> FAIL               [Container Security] -----> PASS
        |                                              |
        v                                              v
[Security Gate]      -----> BLOCKED            [Security Gate]      -----> PASSED
        |                                              |
        X                                              v
   BUILD STOPPED                               [Build & Push]       -----> PASS
                                                       |
                                                       v
                                               [SBOM & Signing]     -----> PASS
                                                       |
                                                       v
                                               DEPLOYED SECURELY
```

## Pipeline URLs

| Scenario | Run ID | Status | URL |
|----------|--------|--------|-----|
| RED | 30568251569 | FAILURE | [View Run](https://github.com/hdmartinezm/secure-software-factory/actions/runs/30568251569) |
| GREEN | 30596948341 | SUCCESS | [View Run](https://github.com/hdmartinezm/secure-software-factory/actions/runs/30596948341) |

## Vulnerabilities Detected and Remediated

| Category | Vulnerability | RED Status | GREEN Status | Remediation |
|----------|--------------|------------|--------------|-------------|
| Secrets | Hardcoded DB password | DETECTED | FIXED | Environment variables |
| Secrets | API keys in code | DETECTED | FIXED | Secrets manager |
| SAST | SQL Injection | DETECTED | FIXED | Parameterized queries |
| SAST | Command Injection | DETECTED | FIXED | Safe subprocess |
| SCA | CVE-2020-14343 (PyYAML) | DETECTED | FIXED | Updated to 6.0.1 |
| SCA | CVE-2023-32681 (requests) | DETECTED | FIXED | Updated to 2.31.0 |
| IaC | S3 public access | DETECTED | FIXED | Block public access |
| IaC | S3 no encryption | DETECTED | FIXED | AES-256 + KMS |
| IaC | IAM Action: "*" | DETECTED | FIXED | Least privilege |
| Container | Running as root | DETECTED | FIXED | USER 1000:1000 |

## Regulatory Compliance Mapping

| Control | Regulation | RED | GREEN |
|---------|------------|-----|-------|
| Encryption at rest | CNBV Art. 316 Bis 17 | FAIL | PASS |
| Access control | SOC 2 CC6.3 | FAIL | PASS |
| Secrets management | SOC 2 CC6.1 | FAIL | PASS |
| Vulnerability mgmt | CNBV Circular 4/2021 | FAIL | PASS |
| Audit trail | SOC 2 CC7.2 | FAIL | PASS |

## Key Takeaways

1. **Pipeline as Gatekeeper**: The security pipeline prevented vulnerable code from reaching production
2. **Shift-Left Security**: Issues caught early in CI/CD, before deployment
3. **Defense in Depth**: Multiple layers caught different vulnerability types
4. **Policy Enforcement**: Custom EFEX policies (EFEX_AWS_001, EFEX-SEC-004) enforced
5. **Developer Workflow**: Clear feedback loop for remediation
6. **Supply Chain Security**: SBOM and signing ensure artifact integrity

## Evidence Files

- `red/pipeline-failure-report.md` - Detailed RED scenario analysis
- `green/pipeline-success-report.md` - Detailed GREEN scenario analysis
- GitHub Actions runs available for full audit trail
