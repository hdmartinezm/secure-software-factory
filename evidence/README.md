# Evidence: Red/Green Security Gate Demonstration

## Overview

This directory contains evidence demonstrating the **break-the-build** security gate functionality. The evidence shows:

1. **🔴 RED Scenario**: Security scans detecting vulnerabilities and blocking the build
2. **🟢 GREEN Scenario**: Security scans passing after remediation

## Quick Demo

```bash
# Run the full demo (recommended)
./scripts/demo-red-green.sh full

# Or run individual scenarios
./scripts/demo-red-green.sh red    # Show failures
./scripts/demo-red-green.sh green  # Show passing
```

## Evidence Structure

```
evidence/
├── red/                          # 🔴 Vulnerable code scan results
│   ├── gitleaks.sarif           # Secrets detection results
│   ├── gitleaks-output.txt      # Scan console output
│   ├── semgrep.sarif            # SAST results
│   ├── semgrep-output.txt
│   ├── trivy-sca.sarif          # Dependency CVE results
│   ├── trivy-sca-output.txt
│   ├── checkov-results.sarif    # IaC misconfigs
│   ├── checkov-output.txt
│   ├── trivy-container.sarif    # Container scan results
│   └── trivy-container-output.txt
├── green/                        # 🟢 Remediated code scan results
│   └── [same structure as red/]
├── sarif/                        # Aggregated SARIF for GitHub
├── sbom.spdx.json               # Software Bill of Materials (SPDX)
├── sbom.cdx.json                # Software Bill of Materials (CycloneDX)
└── README.md                    # This file
```

## Red Scenario - Expected Failures

### Layer 1: Secrets (gitleaks)

**Findings:**
| Secret Type | File | Line | Rule ID |
|-------------|------|------|---------|
| Stripe API Key | vulnerable-app/main.py | 32 | stripe-api-key |
| AWS Secret Key | vulnerable-app/main.py | 33 | aws-secret-access-key |
| SPEI Token | vulnerable-app/main.py | 34 | efex-spei-token |
| Database Password | vulnerable-app/main.py | 30 | generic-password |

**Exit Code:** 1 (BUILD BLOCKED)

### Layer 2: SAST (Semgrep)

**Findings:**
| Severity | Rule | File | Line | Issue |
|----------|------|------|------|-------|
| ERROR | python.lang.security.audit.formatted-sql-query | main.py | 67 | SQL Injection |
| ERROR | python.lang.security.audit.subprocess-shell-true | main.py | 95 | Command Injection |
| ERROR | python.lang.security.audit.dangerous-yaml-load | main.py | 115 | Insecure Deserialization |
| WARNING | efex-sensitive-data-logging | main.py | 68 | Sensitive data in logs |

**Exit Code:** 1 (BUILD BLOCKED)

### Layer 3: SCA (Trivy)

**Findings:**
| Package | Version | CVE | Severity | Fixed In |
|---------|---------|-----|----------|----------|
| pyyaml | 5.3.1 | CVE-2020-14343 | CRITICAL | 5.4 |
| certifi | 2022.12.7 | CVE-2023-37920 | CRITICAL | 2023.7.22 |
| requests | 2.25.1 | CVE-2023-32681 | HIGH | 2.31.0 |
| urllib3 | 1.26.5 | CVE-2023-43804 | HIGH | 2.0.6 |

**Exit Code:** 1 (BUILD BLOCKED)

### Layer 4: IaC (Checkov)

**Findings:**
| Check ID | Resource | Issue |
|----------|----------|-------|
| CKV_AWS_19 | aws_s3_bucket.kyc_documents | S3 Bucket encryption not enabled |
| CKV_AWS_20 | aws_s3_bucket_public_access_block | S3 Block Public Access not configured |
| CKV_AWS_1 | aws_iam_policy.transfer_service | IAM policy allows all actions (*) |
| CKV_AWS_17 | aws_db_instance.transfers | RDS is publicly accessible |
| CKV_AWS_16 | aws_db_instance.transfers | RDS storage not encrypted |
| CKV_AWS_23 | aws_security_group.api_service | Security group allows 0.0.0.0/0 |

**Exit Code:** 1 (BUILD BLOCKED)

### Layer 5: Container (Trivy + Dockerfile)

**Findings:**
| Check | Issue |
|-------|-------|
| EFEX-DOCKER-001 | No USER directive - container runs as root |
| EFEX-DOCKER-002 | Base image not pinned (python:3.9 without digest) |
| DS002 | Running as root user |
| DS026 | No HEALTHCHECK instruction |

**Exit Code:** 1 (BUILD BLOCKED)

---

## Green Scenario - All Passing

### Remediations Applied

| Issue | Remediation |
|-------|-------------|
| Hardcoded secrets | Moved to environment variables (`os.environ.get()`) |
| SQL Injection | Parameterized queries (`cursor.execute(query, params)`) |
| Command Injection | subprocess with `shell=False` and list args |
| YAML Deserialization | `yaml.safe_load()` instead of `yaml.load()` |
| CVEs in dependencies | All packages upgraded to patched versions |
| Container root | Added `USER efex:efex` directive |
| Base image pinning | Added `@sha256:...` digest |
| S3 encryption | Added KMS encryption configuration |
| S3 public access | Blocked all public access |
| IAM permissions | Reduced to specific actions and resources |
| RDS public access | Set `publicly_accessible = false` |
| RDS encryption | Set `storage_encrypted = true` |
| Security groups | Restricted to specific IP ranges/security groups |

### Results

| Layer | Tool | Findings | Status |
|-------|------|----------|--------|
| Secrets | gitleaks | 0 | ✅ PASS |
| SAST | Semgrep | 0 HIGH/CRITICAL | ✅ PASS |
| SCA | Trivy | 0 HIGH/CRITICAL | ✅ PASS |
| IaC | Checkov | 0 failures | ✅ PASS |
| Container | Trivy | 0 HIGH/CRITICAL | ✅ PASS |

**Security Gate: ✅ PASSED**

---

## How to Generate Evidence

### Prerequisites

```bash
# macOS
brew install gitleaks semgrep trivy checkov conftest syft

# Or using pip
pip install semgrep checkov

# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh
```

### Run Demo

```bash
cd secure-software-factory

# Full demo with interactive prompts
./scripts/demo-red-green.sh full

# Just red scenario
./scripts/demo-red-green.sh red

# Just green scenario
./scripts/demo-red-green.sh green
```

### Manual Commands

```bash
# Secrets
gitleaks detect --source . --verbose

# SAST
semgrep scan --config auto --config .semgrep/ vulnerable-app/

# SCA
trivy fs --severity HIGH,CRITICAL .

# IaC
checkov -d infra/ --framework terraform

# Container
docker build -t efex-app:test .
trivy image efex-app:test

# SBOM
syft packages dir:. -o spdx-json > sbom.spdx.json
```

---

## SARIF Reports

All scan results are in SARIF (Static Analysis Results Interchange Format) for:
- GitHub Security tab integration
- Unified vulnerability reporting
- Audit evidence retention

View SARIF files:
```bash
# Pretty print
cat evidence/red/semgrep.sarif | jq '.runs[].results'

# Count findings
cat evidence/red/semgrep.sarif | jq '[.runs[].results[]] | length'
```

---

## Compliance Evidence Mapping

| Evidence File | SOC 2 Control | CNBV Control |
|---------------|---------------|--------------|
| gitleaks.sarif | CC6.1 | Art. 316 Bis |
| semgrep.sarif | CC6.6 | Anexo 1-A |
| trivy-sca.sarif | CC7.1 | Circular 4/2021 |
| checkov-results.sarif | CC6.1, CC6.3 | Art. 316 Bis 17 |
| trivy-container.sarif | CC6.8 | Container Security |
| sbom.spdx.json | CC7.2 | Supply Chain |

---

## Screenshots for Submission

Capture screenshots of:

1. **GitHub Actions Run** (red): Pipeline failing with all 5 layers
2. **Security Tab**: SARIF findings in GitHub Security
3. **Remediation Commit**: Diff showing fixes
4. **GitHub Actions Run** (green): Pipeline passing
5. **SBOM Artifact**: Generated SBOM in artifacts

---

## Contact

Platform Security Team - security@efex.com
