# EFEX Secure Software Factory

> **Tech Challenge: Staff Security Platform Engineer**
> Pipeline DevSecOps & Policy-as-Code Gate

## Overview

This repository demonstrates a **Secure Software Factory** for EFEX, a fintech platform handling treasury and FX operations in the Mexico-US corridor. The implementation includes:

1. **Vulnerable Seed Application** - Intentionally insecure microservice representing common fintech vulnerabilities
2. **Multi-layer DevSecOps Pipeline** - GitHub Actions with Secrets, SAST, SCA, IaC, and Container scanning
3. **Policy-as-Code Gates** - Custom OPA/Conftest and Checkov policies enforcing EFEX security standards
4. **Supply Chain Security** - SBOM generation with Syft and artifact signing with cosign

## Repository Structure

```
secure-software-factory/
├── vulnerable-app/           # Intentionally vulnerable FastAPI microservice
│   ├── main.py              # Application with hardcoded secrets, SQLi, etc.
│   └── requirements.txt     # Dependencies with known CVEs
├── infra/                   # Terraform with security misconfigurations
│   ├── main.tf             # S3 public, IAM *, open SGs
│   ├── providers.tf
│   └── variables.tf
├── policy/                  # Custom security policies
│   ├── terraform/          # OPA/Conftest policies for IaC
│   └── docker/             # Container security policies
├── .github/workflows/       # CI/CD pipeline (GitHub Actions)
│   └── security-pipeline.yml
├── pipelines/               # Multi-platform CI/CD examples
│   ├── azure-pipelines.yml  # Azure DevOps
│   ├── buildspec.yml        # AWS CodeBuild/CodePipeline
│   └── .gitlab-ci.yml       # GitLab CI/CD
├── scripts/
│   └── security-scan.sh     # Universal security scanner (any platform)
├── docs/
│   └── adr/                # Architecture Decision Records
├── evidence/               # Red/Green demonstration artifacts
│   ├── red/               # Pipeline failure evidence
│   └── green/             # Pipeline success after remediation
└── README.md
```

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

### Application Layer (vulnerable-app/main.py)

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

### Infrastructure (infra/main.tf)

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
# Secret scanning
gitleaks detect --source . --config .gitleaks.toml --verbose

# SAST scanning
semgrep scan --config auto --config .semgrep/ ./vulnerable-app

# SCA scanning
trivy fs --severity HIGH,CRITICAL --ignore-unfixed vulnerable-app/

# IaC scanning
checkov -d infra/ --framework terraform

# Container scanning (after build)
docker build -t efex-app:test .
trivy image --severity HIGH,CRITICAL efex-app:test
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

The `evidence/` directory contains screenshots and logs demonstrating:

- **Red (🔴)**: Pipeline failures when vulnerabilities are detected
- **Green (🟢)**: Pipeline success after remediation

See `evidence/README.md` for detailed walkthrough.

## License

Internal use only - EFEX Confidential
