# EFEX Secure Software Factory - GREEN Scenario Evidence

## Pipeline Run Details

| Field | Value |
|-------|-------|
| **Run ID** | 30733265681 |
| **Conclusion** | SUCCESS |
| **Date** | 2026-08-02T04:57:53Z |
| **Branch** | main |
| **Commit** | `3f00265` - fix(pipelines): Update alternative pipelines to use scenario variables |
| **URL** | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30733265681 |

## Security Checks Results

| Check | Status | Duration | Details |
|-------|--------|----------|---------|
| 🔐 Secrets Detection | PASSED | 13s | No hardcoded secrets |
| 🔍 SAST Analysis | PASSED | 41s | No injection vulnerabilities |
| 📦 Dependency Scan (SCA) | PASSED | 20s | Dependencies updated/baselined |
| 🏗️ IaC Security Scan | PASSED | 44s | Infrastructure compliant |
| 🐳 Container Security | PASSED | 1m16s | Non-root user, hardened |
| 🚦 Security Gate | PASSED | 4s | All checks passed |
| 📋 SBOM & Signing | PASSED | 1m22s | SBOM generated, image signed |
| 📊 Pipeline Status | PASSED | 2s | Full pipeline success |

## Remediations Applied

### 1. Secrets Management
- Removed hardcoded database passwords
- Removed API keys from source code
- Implemented environment variable references
- Added `.gitleaks.toml` allowlist for test patterns

### 2. Code Security (SAST)
- Fixed SQL injection with parameterized queries
- Fixed command injection with safe subprocess calls
- Fixed insecure YAML deserialization
- Removed sensitive data from logs

### 3. Dependencies (SCA)
- Updated `requests` to 2.34.2
- Updated `pyyaml` to 6.0.1
- Updated `certifi` to 2026.7.22
- Updated `urllib3` to 2.7.0
- Updated `fastapi` to 0.136.1
- Added `.trivyignore` for baselined transitive CVEs
- Pinned all dependency versions

### 4. Infrastructure (IaC)
- Added S3 encryption (AES-256 + KMS)
- Enabled S3 public access blocks
- Restricted IAM policies to least privilege
- Added VPC flow logs
- Enabled RDS encryption
- Custom OPA policies (EFEX_AWS_001-011)

### 5. Container Security
- Added `USER 1000:1000` directive
- Pinned base image `python:3.11-slim-bookworm`
- Added `HEALTHCHECK` instruction
- Removed unnecessary packages
- Used multi-stage build

## Supply Chain Security

| Artifact | Status |
|----------|--------|
| SBOM (SPDX) | Generated |
| SBOM (CycloneDX) | Generated |
| Container Signature | Signed with Sigstore (keyless) |
| Attestation | Created |

## Job URLs

| Job | Status | URL |
|-----|--------|-----|
| Secrets Detection | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30733265681/job/91457182324 |
| SAST Analysis | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30733265681/job/91457182330 |
| Dependency Scan | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30733265681/job/91457182325 |
| IaC Security | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30733265681/job/91457182312 |
| Container Security | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30733265681/job/91457182318 |
| Security Gate | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30733265681/job/91457282875 |
| SBOM & Signing | PASSED | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30733265681/job/91457291272 |

## Conclusion

After applying security remediations, the pipeline **PASSED** all checks:

1. **All 7 Security Layers** - Validated and passed
2. **Security Gate** - Approved for deployment
3. **Supply Chain** - SBOM generated, artifacts signed with Sigstore
4. **Compliance** - CNBV/SOC2 controls satisfied

This demonstrates the complete DevSecOps workflow: **Detect -> Block -> Remediate -> Deploy**

### Security Gates Summary

| Gate | Tool | Status | Evidence |
|------|------|--------|----------|
| Secrets | Gitleaks | PASSED | No findings |
| SAST | Semgrep | PASSED | No vulnerabilities |
| SCA | Trivy | PASSED | All CVEs remediated/baselined |
| IaC | Checkov + OPA | PASSED | Compliant infrastructure |
| Container | Hadolint + Trivy | PASSED | Non-root, hardened image |

**Total: 5/5 gates passed = Pipeline SUCCESS + SBOM + Signed Image**
