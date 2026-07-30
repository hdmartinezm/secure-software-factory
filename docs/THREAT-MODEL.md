# EFEX Secure Software Factory - Threat Model

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2024-01-15 |
| Author | Platform Security Team |
| Review Status | Draft |
| Classification | Internal |

---

## 1. System Overview

### 1.1 Description

The EFEX Secure Software Factory is a DevSecOps pipeline that builds, tests, scans, and deploys the EFEX Transfer Service - a microservice handling SPEI (Sistema de Pagos Electrónicos Interbancarios) transactions between Mexico and US financial institutions.

### 1.2 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TRUST BOUNDARY: INTERNET                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY: GITHUB                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                     │
│  │  Developer  │───▶│  GitHub     │───▶│  GitHub     │                     │
│  │  Workstation│    │  Repository │    │  Actions    │                     │
│  └─────────────┘    └─────────────┘    └──────┬──────┘                     │
│                                               │                             │
└───────────────────────────────────────────────┼─────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRUST BOUNDARY: AWS                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │    ECR      │◀───│  Container  │───▶│    ECS      │───▶│    RDS      │  │
│  │  Registry   │    │   Image     │    │   Fargate   │    │   MySQL     │  │
│  └─────────────┘    └─────────────┘    └──────┬──────┘    └─────────────┘  │
│                                               │                             │
│                                               ▼                             │
│                                        ┌─────────────┐                      │
│                                        │     S3      │                      │
│                                        │ KYC Docs    │                      │
│                                        └─────────────┘                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      TRUST BOUNDARY: EXTERNAL APIs                          │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                     │
│  │    SPEI     │    │   Banxico   │    │   Banking   │                     │
│  │    API      │    │    API      │    │  Partners   │                     │
│  └─────────────┘    └─────────────┘    └─────────────┘                     │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Assets

| Asset | Description | Sensitivity | Regulatory |
|-------|-------------|-------------|------------|
| SPEI Credentials | API tokens for SPEI transactions | Critical | CNBV |
| CLABE Numbers | Mexican bank account identifiers | High (PII) | LFPDPPP |
| KYC Documents | INE, proof of address, etc. | Critical (PII) | CNBV, LFPDPPP |
| Transaction Data | Transfer amounts, timestamps | High | CNBV, SOC 2 |
| Source Code | Application business logic | Medium | Trade Secret |
| Infrastructure Config | Terraform, Kubernetes | High | SOC 2 |
| Pipeline Secrets | AWS keys, GitHub tokens | Critical | SOC 2 |

---

## 2. Threat Analysis (STRIDE)

### 2.1 Application Threats

#### T-APP-001: SQL Injection
| Field | Value |
|-------|-------|
| Category | Tampering |
| Target | Database queries |
| Attack Vector | Malicious input in CLABE/account fields |
| Impact | Data exfiltration, unauthorized transfers |
| Likelihood | High (common vulnerability) |
| Risk Level | **Critical** |
| Mitigation | Parameterized queries, input validation |
| Detection | Semgrep SAST (efex-sql-injection-transfer) |

#### T-APP-002: Command Injection
| Field | Value |
|-------|-------|
| Category | Elevation of Privilege |
| Target | Report generation, export functions |
| Attack Vector | Shell metacharacters in user input |
| Impact | Remote code execution, data theft |
| Likelihood | Medium |
| Risk Level | **Critical** |
| Mitigation | subprocess with shell=False, input validation |
| Detection | Semgrep SAST (efex-command-injection) |

#### T-APP-003: Insecure Deserialization
| Field | Value |
|-------|-------|
| Category | Tampering, Elevation of Privilege |
| Target | YAML configuration import |
| Attack Vector | Malicious YAML payload (CVE-2020-14343) |
| Impact | Remote code execution |
| Likelihood | Medium |
| Risk Level | **Critical** |
| Mitigation | yaml.safe_load(), upgrade PyYAML |
| Detection | Semgrep SAST (efex-unsafe-yaml-load), Trivy SCA |

#### T-APP-004: Hardcoded Secrets
| Field | Value |
|-------|-------|
| Category | Information Disclosure |
| Target | Source code, configuration |
| Attack Vector | Git history mining, code leak |
| Impact | Unauthorized API access, fund theft |
| Likelihood | High |
| Risk Level | **Critical** |
| Mitigation | Secrets Manager, environment variables |
| Detection | gitleaks (efex-spei-token, efex-database-password) |

### 2.2 Infrastructure Threats

#### T-INFRA-001: Public S3 Bucket
| Field | Value |
|-------|-------|
| Category | Information Disclosure |
| Target | KYC documents bucket |
| Attack Vector | Direct URL access, bucket enumeration |
| Impact | PII exposure, regulatory violation |
| Likelihood | High (common misconfiguration) |
| Risk Level | **Critical** |
| Mitigation | Block public access, encryption, IAM policies |
| Detection | Checkov (CKV_AWS_19, CKV_AWS_20), OPA (EFEX-TF-S3-*) |

#### T-INFRA-002: Overprivileged IAM
| Field | Value |
|-------|-------|
| Category | Elevation of Privilege |
| Target | IAM policies with Action:* |
| Attack Vector | Compromised credential escalation |
| Impact | Full AWS account compromise |
| Likelihood | Medium |
| Risk Level | **Critical** |
| Mitigation | Least privilege policies, resource constraints |
| Detection | Checkov (CKV_AWS_1), OPA (EFEX-TF-IAM-*) |

#### T-INFRA-003: Public Database
| Field | Value |
|-------|-------|
| Category | Information Disclosure, Tampering |
| Target | RDS MySQL instance |
| Attack Vector | Direct connection from internet |
| Impact | Data theft, manipulation |
| Likelihood | Medium |
| Risk Level | **Critical** |
| Mitigation | Private subnet, security groups, encryption |
| Detection | Checkov (CKV_AWS_17), OPA (EFEX-TF-DB-*) |

#### T-INFRA-004: Unencrypted Data at Rest
| Field | Value |
|-------|-------|
| Category | Information Disclosure |
| Target | S3, RDS, CloudWatch Logs |
| Attack Vector | Physical media theft, unauthorized access |
| Impact | Data exposure, regulatory violation |
| Likelihood | Low |
| Risk Level | **High** |
| Mitigation | KMS encryption for all storage |
| Detection | Checkov (CKV_AWS_19, CKV_AWS_16), OPA (EFEX-TF-S3-001) |

### 2.3 Supply Chain Threats

#### T-SUPPLY-001: Malicious Dependency
| Field | Value |
|-------|-------|
| Category | Tampering |
| Target | Python packages (PyPI) |
| Attack Vector | Typosquatting, package hijacking |
| Impact | Backdoor in application |
| Likelihood | Medium |
| Risk Level | **High** |
| Mitigation | Pinned versions, SBOM, dependency review |
| Detection | Trivy SCA, Dependabot |

#### T-SUPPLY-002: Vulnerable Dependency
| Field | Value |
|-------|-------|
| Category | Varies by CVE |
| Target | Third-party libraries |
| Attack Vector | Exploiting known CVEs |
| Impact | Varies (RCE to DoS) |
| Likelihood | High |
| Risk Level | **High** |
| Mitigation | Continuous scanning, rapid patching |
| Detection | Trivy SCA (exit-code 1 on CRITICAL/HIGH) |

#### T-SUPPLY-003: Compromised Base Image
| Field | Value |
|-------|-------|
| Category | Tampering |
| Target | Docker base image |
| Attack Vector | Registry compromise, tag overwriting |
| Impact | Backdoor in all deployments |
| Likelihood | Low |
| Risk Level | **Critical** |
| Mitigation | Pinned digests, image signing, scanning |
| Detection | Trivy container, cosign verification |

#### T-SUPPLY-004: CI/CD Pipeline Compromise
| Field | Value |
|-------|-------|
| Category | Tampering, Elevation of Privilege |
| Target | GitHub Actions workflow |
| Attack Vector | Malicious PR, workflow injection |
| Impact | Credential theft, malicious deployment |
| Likelihood | Low |
| Risk Level | **Critical** |
| Mitigation | Branch protection, signed commits, SLSA |
| Detection | cosign provenance verification |

### 2.4 Container Threats

#### T-CONT-001: Container Running as Root
| Field | Value |
|-------|-------|
| Category | Elevation of Privilege |
| Target | Container runtime |
| Attack Vector | Container escape via root privileges |
| Impact | Host system compromise |
| Likelihood | Medium |
| Risk Level | **High** |
| Mitigation | Non-root USER, read-only filesystem |
| Detection | Trivy (DS002), OPA (EFEX-DOCKER-001) |

#### T-CONT-002: Secrets in Container Image
| Field | Value |
|-------|-------|
| Category | Information Disclosure |
| Target | Docker image layers |
| Attack Vector | Image layer inspection |
| Impact | Credential exposure |
| Likelihood | Medium |
| Risk Level | **High** |
| Mitigation | Multi-stage builds, runtime injection |
| Detection | gitleaks on image, OPA (EFEX-DOCKER-007) |

---

## 3. Risk Summary

### 3.1 Risk Matrix

```
                    LIKELIHOOD
              Low    Medium    High
         ┌─────────┬─────────┬─────────┐
    High │ MEDIUM  │  HIGH   │CRITICAL │
         ├─────────┼─────────┼─────────┤
IMPACT   │         │T-CONT-01│T-APP-04 │
  Medium │  LOW    │ MEDIUM  │  HIGH   │
         ├─────────┼─────────┼─────────┤
         │         │         │         │
    Low  │  LOW    │  LOW    │ MEDIUM  │
         └─────────┴─────────┴─────────┘
```

### 3.2 Top Risks

| Rank | Threat ID | Risk | Mitigation Status |
|------|-----------|------|-------------------|
| 1 | T-APP-001 | SQL Injection | ✅ Parameterized queries |
| 2 | T-APP-004 | Hardcoded Secrets | ✅ gitleaks detection |
| 3 | T-INFRA-001 | Public S3 | ✅ Checkov + OPA policies |
| 4 | T-SUPPLY-003 | Base Image Compromise | ✅ cosign signing |
| 5 | T-CONT-001 | Container Root | ✅ Trivy + OPA policies |

---

## 4. Security Controls Mapping

| Control | Threats Mitigated | Layer | Tool |
|---------|-------------------|-------|------|
| Parameterized queries | T-APP-001 | Application | Semgrep |
| Input validation | T-APP-001, T-APP-002 | Application | Semgrep |
| yaml.safe_load | T-APP-003 | Application | Semgrep |
| Secrets Manager | T-APP-004 | Application | gitleaks |
| S3 encryption + ACL | T-INFRA-001, T-INFRA-004 | IaC | Checkov, OPA |
| IAM least privilege | T-INFRA-002 | IaC | Checkov, OPA |
| Private subnets | T-INFRA-003 | IaC | Checkov, OPA |
| KMS encryption | T-INFRA-004 | IaC | Checkov, OPA |
| Pinned dependencies | T-SUPPLY-001 | SCA | Trivy |
| CVE scanning | T-SUPPLY-002 | SCA | Trivy |
| Image signing | T-SUPPLY-003 | Container | cosign |
| SLSA provenance | T-SUPPLY-004 | Pipeline | GitHub Actions |
| Non-root USER | T-CONT-001 | Container | Trivy, OPA |
| Multi-stage build | T-CONT-002 | Container | Hadolint |

---

## 5. Residual Risks

| Risk | Description | Acceptance Rationale |
|------|-------------|---------------------|
| Zero-day CVEs | Vulnerabilities not yet in databases | Accept: Continuous monitoring minimizes window |
| Insider threat | Malicious employee with access | Mitigate: Audit logging, least privilege |
| GitHub compromise | Platform-level breach | Accept: Industry-standard platform |

---

## 6. Review Schedule

- **Quarterly**: Full threat model review
- **Monthly**: New threat assessment
- **Per-release**: Security control verification
- **On-demand**: After security incidents

---

## Appendix A: Regulatory Mapping

| Threat Category | CNBV/IFPE | SOC 2 | OWASP |
|-----------------|-----------|-------|-------|
| Injection | Anexo 1-A | CC6.6 | A03:2021 |
| Secrets Exposure | Art. 316 Bis | CC6.1 | A07:2021 |
| Data Encryption | Art. 316 Bis 17 | CC6.1 | A02:2021 |
| Access Control | Circular 4/2021 | CC6.3 | A01:2021 |
| Supply Chain | - | CC7.1 | A06:2021 |
