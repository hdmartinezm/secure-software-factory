# EFEX Secure Software Factory

> **Tech Challenge: Staff Security Platform Engineer**
> Pipeline DevSecOps & Policy-as-Code Gate

[![Security Pipeline](https://github.com/hdmartinezm/secure-software-factory/actions/workflows/security-pipeline.yml/badge.svg)](https://github.com/hdmartinezm/secure-software-factory/actions/workflows/security-pipeline.yml)

## Overview

This repository demonstrates a **Secure Software Factory** for EFEX, a fintech platform handling treasury and FX operations in the Mexico-US corridor. The implementation includes:

1. **Vulnerable Demo Application** (`vulnerable/`) - Intentionally insecure code with DEMO secrets (not real credentials)
2. **Remediated Application** (`remediated/`) - Secure version with all vulnerabilities fixed
3. **Multi-layer DevSecOps Pipeline** - GitHub Actions with 7 security gates
4. **Policy-as-Code Gates** - Custom Gitleaks, Semgrep, and Checkov policies for EFEX
5. **Supply Chain Security** - SBOM generation with Syft and artifact signing with cosign

## Pipeline Evidence (Live Runs)

| Scenario | Run ID | Status | Security Gates | Link |
|----------|--------|--------|----------------|------|
| **RED** | 30651059422 | FAILURE | 4/5 failed | [View Run](https://github.com/hdmartinezm/secure-software-factory/actions/runs/30651059422) |
| **GREEN** | 30596948341 | SUCCESS | 5/5 passed | [View Run](https://github.com/hdmartinezm/secure-software-factory/actions/runs/30596948341) |

### RED Scenario Findings

| Security Gate | Tool | Findings | Status |
|---------------|------|----------|--------|
| Secrets Detection | Gitleaks | 4 demo secrets | FAILED |
| SAST Analysis | Semgrep | 13 vulnerabilities | FAILED |
| Dependency Scan (SCA) | Trivy | HIGH/CRITICAL CVEs | FAILED |
| IaC Security | Checkov | 28 misconfigurations | FAILED |
| Container Security | Trivy | 0 (secure Dockerfile) | PASSED |

## Red/Green Comparison

| Component | Vulnerable (Red) | Remediated (Green) |
|-----------|-----------------|-------------------|
| **FastAPI App** | Hardcoded demo secrets (`HARDCODED_SECRET_FOR_DEMO`) | Environment variables |
| **SQL Queries** | String concatenation (injection) | Parameterized queries |
| **Subprocess** | `shell=True` (command injection) | `shell=False` with arg list |
| **YAML** | `yaml.load()` (code execution) | `yaml.safe_load()` |
| **Logging** | Logs passwords/tokens | Redacted sensitive data |
| **Docker** | Runs as root, unpinned image | Non-root user, pinned image |
| **Terraform S3** | Public, no encryption | Private, AES-256 + KMS |
| **Terraform IAM** | `Action: "*"` wildcard | Least privilege |
| **Dependencies** | Known CVEs (PyYAML 5.3.1) | Patched versions |

## Repository Structure

```
secure-software-factory/
├── vulnerable/              # INTENTIONALLY INSECURE (for demo)
│   ├── app/
│   │   ├── main.py         # Demo secrets, SQLi, command injection
│   │   └── requirements.txt # Dependencies with known CVEs
│   ├── Dockerfile          # Runs as root, unpinned image
│   └── infra/
│       └── main.tf         # S3 public, IAM *, open SGs
│
├── remediated/              # SECURE VERSION
│   ├── app/
│   │   ├── main.py         # Env vars, parameterized queries
│   │   └── requirements.txt # Patched dependencies
│   ├── Dockerfile          # Non-root, multi-stage, healthcheck
│   └── infra/
│       └── main.tf         # Encrypted, least privilege
│
├── .github/workflows/       # CI/CD pipeline (GitHub Actions)
│   └── security-pipeline.yml
├── pipelines/               # Multi-platform CI/CD examples
│   ├── azure-pipelines.yml  # Azure DevOps
│   ├── buildspec.yml        # AWS CodeBuild/CodePipeline
│   └── .gitlab-ci.yml       # GitLab CI/CD
├── scripts/
│   └── security-scan.sh     # Universal security scanner
├── policy/                  # Custom security policies
│   ├── terraform/          # OPA/Conftest policies
│   └── docker/             # Container policies
├── .semgrep/               # Custom SAST rules
├── .gitleaks.toml          # Secret detection config
├── evidence/               # Red/Green demonstration
│   ├── red/               # Pipeline failure evidence
│   └── green/             # Pipeline success evidence
└── docs/adr/               # Architecture Decision Records
```

## Demo Secrets

The `vulnerable/` folder contains **intentional demo secrets** that are:
- Clearly marked as demo values (`HARDCODED_SECRET_FOR_DEMO`, `DEMO_API_KEY_*`)
- Detected by Gitleaks and Semgrep custom rules
- **Not real credentials** - safe for public repositories

```python
# vulnerable/app/main.py - Demo secrets (NOT REAL)
DATABASE_PASSWORD = "HARDCODED_SECRET_FOR_DEMO_efex2024"
SPEI_API_TOKEN = "DEMO_API_KEY_spei_tk_12345678"
JWT_SECRET_KEY = "DEMO_JWT_SECRET_super_insecure_key"
AWS_ACCESS_KEY = "AKIADEMO12345EXAMPLE"
AWS_SECRET_KEY = "DEMO_SECRET_wJalrXUtnFEMI_K7MDENG_bPxRfiCY"
```

**Custom Gitleaks rules** in `.gitleaks.toml` detect these patterns:
- `efex-demo-hardcoded-secret` - HARDCODED_SECRET_FOR_DEMO*
- `efex-demo-api-key` - DEMO_API_KEY_*
- `efex-demo-jwt-secret` - DEMO_JWT_SECRET_*
- `efex-demo-generic` - DEMO_SECRET_*
- `efex-demo-aws-key` - AKIADEMO*

This approach allows demonstrating the Red scenario without exposing real secrets or triggering GitHub's push protection.

## Platform-Agnostic Security Pipeline

The security tools used in this factory are **CLI-based and platform-agnostic**. The same scans work on any CI/CD platform:

### Supported Platforms

| Platform | Configuration File | Status |
|----------|-------------------|--------|
| GitHub Actions | `.github/workflows/security-pipeline.yml` | Primary |
| Azure DevOps | `pipelines/azure-pipelines.yml` | Example |
| AWS CodePipeline | `pipelines/buildspec.yml` | Example |
| GitLab CI/CD | `pipelines/.gitlab-ci.yml` | Example |
| Jenkins | Use `scripts/security-scan.sh` | Portable |
| CircleCI | Use `scripts/security-scan.sh` | Portable |
| Local/Dev | Use `scripts/security-scan.sh` | Portable |

### Core Security Tools

All pipelines use the same open-source, industry-standard tools:

| Layer | Tool | Purpose | Output |
|-------|------|---------|--------|
| Secrets | [Gitleaks](https://github.com/gitleaks/gitleaks) | Detect hardcoded secrets | SARIF |
| SAST | [Semgrep](https://github.com/returntocorp/semgrep) | Static code analysis | SARIF |
| SCA | [Trivy](https://github.com/aquasecurity/trivy) | Dependency vulnerabilities | SARIF |
| IaC | [Checkov](https://github.com/bridgecrewio/checkov) | Infrastructure security | SARIF |
| Container | [Trivy](https://github.com/aquasecurity/trivy) + [Hadolint](https://github.com/hadolint/hadolint) | Image vulnerabilities | SARIF |
| SBOM | [Syft](https://github.com/anchore/syft) | Software Bill of Materials | SPDX, CycloneDX |
| Signing | [Cosign](https://github.com/sigstore/cosign) | Artifact signing | Sigstore |

### Universal Security Scanner

The `scripts/security-scan.sh` script runs all security checks on **any platform**:

```bash
# Run all security scans
./scripts/security-scan.sh

# Soft-fail mode (for CI debugging)
./scripts/security-scan.sh --soft-fail

# Skip IaC scans
./scripts/security-scan.sh --skip-iac
```

Output is written to `evidence/scan-results/` in SARIF format for unified reporting.

### Why Platform-Agnostic?

1. **No vendor lock-in**: Switch CI/CD platforms without rewriting security scans
2. **Consistent security**: Same tools = same detection across environments
3. **Local development**: Developers can run scans before pushing
4. **Compliance**: Easier to demonstrate control consistency to auditors

## Vulnerability Matrix

### Application Layer (vulnerable/app/main.py)

| ID | Vulnerability | Type | Detection Tool | CVE/CWE | Regulatory Impact |
|----|--------------|------|----------------|---------|-------------------|
| EFEX-VULN-001 | Hardcoded secrets (DB password, API keys) | Secrets | gitleaks | CWE-798 | SOC 2 CC6.1, CNBV Art. 316 Bis |
| EFEX-VULN-002 | SQL Injection in account lookup | SAST | Semgrep | CWE-89 | SOC 2 CC6.6, OWASP A03 |
| EFEX-VULN-003 | Command Injection via subprocess | SAST | Semgrep | CWE-78 | SOC 2 CC6.6, OWASP A03 |
| EFEX-VULN-004 | Insecure YAML deserialization | SAST | Semgrep | CVE-2020-14343 | RCE risk |
| EFEX-VULN-005 | Sensitive data in logs | SAST | Semgrep | CWE-532 | CNBV data protection |

### Dependencies (requirements.txt)

| ID | Vulnerability | Package | CVE | CVSS | Detection Tool |
|----|--------------|---------|-----|------|----------------|
| EFEX-VULN-006a | SSRF vulnerability | requests==2.25.1 | CVE-2023-32681 | 6.1 | Trivy, Snyk |
| EFEX-VULN-006b | Arbitrary code execution | pyyaml==5.3.1 | CVE-2020-14343 | 9.8 CRITICAL | Trivy, Snyk |
| EFEX-VULN-006c | ReDoS | py==1.10.0 | CVE-2022-42969 | 7.5 | Trivy, Snyk |
| EFEX-VULN-006d | Buffer overflow | numpy==1.19.4 | CVE-2021-41496 | 7.5 | Trivy, Snyk |
| EFEX-VULN-006e | Certificate bypass | certifi==2022.12.7 | CVE-2023-37920 | 9.8 CRITICAL | Trivy, Snyk |

### Container (Dockerfile)

| ID | Vulnerability | Issue | Detection Tool | Check ID |
|----|--------------|-------|----------------|----------|
| EFEX-VULN-007 | Running as root | No USER directive | Trivy | DS002 |
| EFEX-VULN-008 | Unpinned base image | `python:3.9` without digest | Trivy | DS001 |
| EFEX-VULN-009 | Secrets in build context | COPY . . includes secrets | Manual |
| EFEX-VULN-010 | No HEALTHCHECK | Missing health endpoint | Trivy | DS026 |
| EFEX-VULN-011 | Unnecessary packages | curl, wget, netcat installed | Trivy |
| EFEX-VULN-012 | ADD instead of COPY | URL fetch risk | Hadolint | DL3020 |

### Infrastructure (vulnerable/infra/main.tf)

| ID | Vulnerability | Resource | Detection Tool | Check ID | Regulatory Impact |
|----|--------------|----------|----------------|----------|-------------------|
| EFEX-VULN-013 | S3 without encryption | aws_s3_bucket.kyc_documents | Checkov | CKV_AWS_19 | CNBV Art. 316 Bis 17 |
| EFEX-VULN-014 | S3 public access | aws_s3_bucket_public_access_block | Checkov | CKV_AWS_20/21 | LFPDPPP |
| EFEX-VULN-015 | IAM Action: "*" | aws_iam_policy.transfer_service | Checkov | CKV_AWS_1 | SOC 2 CC6.3 |
| EFEX-VULN-016 | IAM Resource: "*" | aws_iam_policy.transfer_service | Checkov | CKV_AWS_49 | SOC 2 CC6.3 |
| EFEX-VULN-017 | SG open to 0.0.0.0/0 | aws_security_group.api_service | Checkov | CKV_AWS_23/24/25 | SOC 2 CC6.6 |
| EFEX-VULN-018 | RDS without encryption | aws_db_instance.transfers | Checkov | CKV_AWS_16 | CNBV encryption |
| EFEX-VULN-019 | RDS publicly accessible | aws_db_instance.transfers | Checkov | CKV_AWS_17 | Network segmentation |
| EFEX-VULN-020 | CloudWatch without KMS | aws_cloudwatch_log_group | Checkov | CKV_AWS_97 | SOC 2 CC6.1 |
| EFEX-VULN-021 | No VPC Flow Logs | aws_vpc.main | Checkov | CKV_AWS_12 | SOC 2 CC7.1 |

## Regulatory Mapping

| Control Area | CNBV/IFPE | SOC 2 | EFEX Vulnerability Coverage |
|--------------|-----------|-------|---------------------------|
| Encryption at Rest | Art. 316 Bis 17 | CC6.1 | EFEX-VULN-013, 018, 020 |
| Access Control | Circular 4/2021 | CC6.3 | EFEX-VULN-015, 016, 017 |
| Network Segmentation | Anexo 1-A | CC6.6 | EFEX-VULN-017, 019 |
| Secrets Management | Art. 316 Bis | CC6.1 | EFEX-VULN-001 |
| Vulnerability Management | Circular 4/2021 | CC7.1 | EFEX-VULN-006a-e |
| Audit Trail | Anexo 1-A | CC7.2 | EFEX-VULN-005, 021 |

## Quick Start

### Prerequisites

- Docker
- Python 3.9+
- Security tools: gitleaks, semgrep, trivy, checkov (see install commands below)

### Install Security Tools

```bash
# macOS (Homebrew)
brew install gitleaks trivy
pip install semgrep checkov

# Linux
curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar xz -C /usr/local/bin
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
pip install semgrep checkov
```

### Run Security Scans Locally

**Option 1: Universal Scanner (Recommended)**

```bash
# Clone the repository
git clone https://github.com/hdmartinezm/secure-software-factory.git
cd secure-software-factory

# Run all security scans with single command
./scripts/security-scan.sh

# Results saved to evidence/scan-results/
```

**Option 2: Individual Tools**

```bash
# Secret scanning (will detect demo secrets in vulnerable/)
gitleaks detect --source . --config .gitleaks.toml --verbose

# SAST scanning (vulnerable code)
semgrep scan --config auto --config .semgrep/ ./vulnerable/app

# SCA scanning (vulnerable dependencies)
trivy fs --severity HIGH,CRITICAL --ignore-unfixed vulnerable/app/

# IaC scanning (vulnerable infrastructure)
checkov -d vulnerable/infra/ --framework terraform

# Container scanning (vulnerable Dockerfile)
docker build -f vulnerable/Dockerfile -t efex-vulnerable:test vulnerable/
trivy image --severity HIGH,CRITICAL efex-vulnerable:test

# Container scanning (remediated Dockerfile)
docker build -f remediated/Dockerfile -t efex-secure:test remediated/
trivy image --severity HIGH,CRITICAL efex-secure:test
```

### Trigger Pipeline

**GitHub Actions:**
```bash
git push origin feature/demo
# Or manually: gh workflow run security-pipeline.yml
```

**Azure DevOps:**
```bash
# Copy pipelines/azure-pipelines.yml to your repo
# Configure pipeline in Azure DevOps project settings
```

**AWS CodePipeline:**
```bash
# Use pipelines/buildspec.yml with CodeBuild
# Configure CodePipeline with CodeCommit source
```

**GitLab CI:**
```bash
# Copy pipelines/.gitlab-ci.yml to .gitlab-ci.yml in repo root
```

## Evidence Structure

The `evidence/` directory contains detailed reports demonstrating the Red/Green scenarios:

```
evidence/
├── red/
│   └── pipeline-failure-report.md   # Detailed RED scenario analysis
├── green/
│   └── pipeline-success-report.md   # Detailed GREEN scenario analysis
└── scenario-comparison.md           # Side-by-side comparison
```

### Key Evidence Files

| File | Description |
|------|-------------|
| `evidence/red/pipeline-failure-report.md` | Run 30651059422 - 4 gates failed, 45+ findings |
| `evidence/green/pipeline-success-report.md` | Run 30596948341 - All gates passed |
| `evidence/scenario-comparison.md` | Visual comparison, compliance mapping |

### What the Pipeline Validates

```
┌─────────────────────────────────────────────────────────────────────┐
│                    EFEX Security Pipeline                           │
├─────────────────────────────────────────────────────────────────────┤
│  vulnerable/                          │  Main Branch                │
│  ─────────────                        │  ───────────                │
│  [Secrets]     → FAIL (4 secrets)     │  [Container] → PASS         │
│  [SAST]        → FAIL (13 vulns)      │  [SBOM]      → Generated    │
│  [SCA]         → FAIL (CVEs)          │  [Signing]   → Cosign       │
│  [IaC]         → FAIL (28 issues)     │                             │
│                                       │                             │
│  ════════════════════════════════     │  ════════════════════════   │
│  🚫 SECURITY GATE: BLOCKED            │  ✅ SECURITY GATE: PASSED   │
└─────────────────────────────────────────────────────────────────────┘
```

## License

Internal use only - EFEX Confidential
