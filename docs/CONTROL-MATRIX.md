# EFEX Security Control Matrix

## Quick Reference: Control → Tool → Policy → Evidence

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                           EFEX SECURITY CONTROL MATRIX                                  │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│  CONTROL CATEGORY          TOOL              POLICY ID              EVIDENCE           │
│  ─────────────────         ────              ─────────              ────────           │
│                                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ SECRETS MANAGEMENT                                                              │   │
│  ├─────────────────────────────────────────────────────────────────────────────────┤   │
│  │ Hardcoded API keys      gitleaks          stripe-api-key         gitleaks.sarif │   │
│  │ Hardcoded DB passwords  gitleaks          efex-database-password gitleaks.sarif │   │
│  │ SPEI tokens             gitleaks          efex-spei-token        gitleaks.sarif │   │
│  │ AWS credentials         gitleaks          aws-secret-access-key  gitleaks.sarif │   │
│  │ JWT secrets             gitleaks          jwt-secret             gitleaks.sarif │   │
│  │ CLABE numbers           gitleaks          efex-clabe             gitleaks.sarif │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ APPLICATION SECURITY (SAST)                                                     │   │
│  ├─────────────────────────────────────────────────────────────────────────────────┤   │
│  │ SQL Injection           Semgrep           efex-sql-injection     semgrep.sarif  │   │
│  │ Command Injection       Semgrep           efex-command-injection semgrep.sarif  │   │
│  │ YAML Deserialization    Semgrep           efex-unsafe-yaml-load  semgrep.sarif  │   │
│  │ Sensitive Data Logging  Semgrep           efex-sensitive-logging semgrep.sarif  │   │
│  │ Debug Mode Enabled      Semgrep           efex-debug-enabled     semgrep.sarif  │   │
│  │ Weak Cryptography       Semgrep           efex-weak-crypto-md5   semgrep.sarif  │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ DEPENDENCY SECURITY (SCA)                                                       │   │
│  ├─────────────────────────────────────────────────────────────────────────────────┤   │
│  │ Critical CVEs           Trivy             --severity CRITICAL    trivy-sca.sarif│   │
│  │ High CVEs               Trivy             --severity HIGH        trivy-sca.sarif│   │
│  │ License Compliance      Syft              SBOM analysis          sbom.spdx.json │   │
│  │ Outdated Dependencies   Dependabot        dependabot.yml         GitHub alerts  │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ INFRASTRUCTURE SECURITY (IaC)                                                   │   │
│  ├─────────────────────────────────────────────────────────────────────────────────┤   │
│  │                                                                                 │   │
│  │  S3 SECURITY                                                                    │   │
│  │  ───────────                                                                    │   │
│  │  S3 Encryption          Checkov+OPA       CKV_AWS_19/EFEX-TF-S3-001  checkov.sarif│ │
│  │  S3 Public Access       Checkov+OPA       CKV_AWS_20/EFEX-TF-S3-002  checkov.sarif│ │
│  │  S3 Public ACL          OPA               EFEX-TF-S3-003         conftest.json  │   │
│  │  S3 Versioning          OPA               EFEX-TF-S3-004         conftest.json  │   │
│  │                                                                                 │   │
│  │  IAM SECURITY                                                                   │   │
│  │  ────────────                                                                   │   │
│  │  IAM Action:*           Checkov+OPA       CKV_AWS_1/EFEX-TF-IAM-001  checkov.sarif│ │
│  │  IAM Resource:*         OPA               EFEX-TF-IAM-002        conftest.json  │   │
│  │  IAM Service:*          OPA               EFEX-TF-IAM-003        conftest.json  │   │
│  │  Trust Policy           OPA               EFEX-TF-IAM-004        conftest.json  │   │
│  │                                                                                 │   │
│  │  NETWORK SECURITY                                                               │   │
│  │  ────────────────                                                               │   │
│  │  SG Open 0.0.0.0/0      Checkov+OPA       CKV_AWS_23/EFEX-TF-NET-001 checkov.sarif│ │
│  │  SSH Public             OPA               EFEX-TF-NET-002        conftest.json  │   │
│  │  DB Port Public         OPA               EFEX-TF-NET-003        conftest.json  │   │
│  │  All Ports Open         OPA               EFEX-TF-NET-004        conftest.json  │   │
│  │  VPC Flow Logs          OPA               EFEX-TF-NET-005        conftest.json  │   │
│  │                                                                                 │   │
│  │  DATABASE SECURITY                                                              │   │
│  │  ─────────────────                                                              │   │
│  │  RDS Encryption         Checkov+OPA       CKV_AWS_16/EFEX-TF-DB-001  checkov.sarif│ │
│  │  RDS Public Access      Checkov+OPA       CKV_AWS_17/EFEX-TF-DB-002  checkov.sarif│ │
│  │  RDS Deletion Protect   OPA               EFEX-TF-DB-003         conftest.json  │   │
│  │  RDS Backup Retention   OPA               EFEX-TF-DB-004         conftest.json  │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ CONTAINER SECURITY                                                              │   │
│  ├─────────────────────────────────────────────────────────────────────────────────┤   │
│  │ Running as Root         Trivy+OPA         DS002/EFEX-DOCKER-001  trivy.sarif    │   │
│  │ Unpinned Base Image     OPA               EFEX-DOCKER-002        conftest.json  │   │
│  │ No HEALTHCHECK          Trivy             DS026                  trivy.sarif    │   │
│  │ ADD vs COPY             OPA               EFEX-DOCKER-004        conftest.json  │   │
│  │ Unnecessary Packages    OPA               EFEX-DOCKER-005        conftest.json  │   │
│  │ Privileged Ports        OPA               EFEX-DOCKER-006        conftest.json  │   │
│  │ Secrets in ENV          OPA               EFEX-DOCKER-007        conftest.json  │   │
│  │ Image Vulnerabilities   Trivy             --severity HIGH,CRIT   trivy.sarif    │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │ SUPPLY CHAIN SECURITY                                                           │   │
│  ├─────────────────────────────────────────────────────────────────────────────────┤   │
│  │ SBOM Generation         Syft              SPDX 2.3               sbom.spdx.json │   │
│  │ SBOM Generation         Syft              CycloneDX 1.4          sbom.cdx.json  │   │
│  │ Image Signing           cosign            Keyless (Sigstore)     Rekor log      │   │
│  │ SBOM Attestation        cosign            spdxjson predicate     Registry       │   │
│  │ Provenance              SLSA Generator    SLSA Level 2           Attestation    │   │
│  │ Signature Verification  cosign verify     OIDC issuer check      Deploy gate    │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│                                                                                         │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Regulatory Control Cross-Reference

### By Regulation

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                        │
│  CNBV/IFPE                          SOC 2                         BANXICO             │
│  ─────────                          ─────                         ───────             │
│                                                                                        │
│  Art. 316 Bis ──────────────────┬── CC6.1 ─────────────────────── Cap. IV            │
│  (Secrets)                      │   (Logical Access)              (Seguridad)         │
│    ├─ gitleaks                  │     ├─ gitleaks                   ├─ gitleaks      │
│    ├─ Checkov IAM               │     ├─ Checkov IAM                ├─ Checkov       │
│    └─ OPA IAM                   │     └─ OPA IAM                    └─ OPA           │
│                                 │                                                      │
│  Art. 316 Bis 17 ───────────────┼── CC6.1 ─────────────────────── Cap. IV            │
│  (Encryption)                   │   (Encryption)                  (Cifrado)           │
│    ├─ Checkov S3 (CKV_AWS_19)   │     ├─ Checkov S3                 ├─ Checkov S3   │
│    ├─ Checkov RDS (CKV_AWS_16)  │     ├─ Checkov RDS                ├─ Checkov RDS  │
│    ├─ OPA EFEX-TF-S3-001        │     └─ OPA DB policies            └─ OPA policies │
│    └─ OPA EFEX-TF-DB-001        │                                                     │
│                                 │                                                      │
│  Art. 316 Bis 18 ───────────────┼── CC6.3 ─────────────────────── Cap. IV            │
│  (Access Control)               │   (Authorization)               (Acceso)            │
│    ├─ OPA EFEX-TF-IAM-*         │     ├─ OPA EFEX-TF-IAM-*          ├─ OPA IAM      │
│    ├─ Checkov CKV_AWS_1         │     ├─ Checkov IAM                ├─ Checkov      │
│    └─ Trivy DS002 (non-root)    │     └─ Trivy DS002                └─ Trivy        │
│                                 │                                                      │
│  Art. 316 Bis 19 ───────────────┼── CC6.6 ─────────────────────── Cap. IV            │
│  (Vulnerability Mgmt)           │   (System Operations)           (Vulnerabilidades)  │
│    ├─ Semgrep SAST              │     ├─ Semgrep SAST               ├─ Semgrep      │
│    ├─ Trivy SCA                 │     ├─ Trivy SCA                  ├─ Trivy        │
│    ├─ Trivy Container           │     ├─ Trivy Container            ├─ Trivy        │
│    └─ Checkov IaC               │     └─ Checkov IaC                └─ Checkov      │
│                                 │                                                      │
│  Anexo 1-A ─────────────────────┼── CC6.7 ─────────────────────── Cap. VI            │
│  (Tech Requirements)            │   (Change Management)           (Supply Chain)      │
│    ├─ cosign signing            │     ├─ cosign signing             ├─ Syft SBOM    │
│    ├─ Syft SBOM                 │     ├─ SLSA provenance            ├─ cosign       │
│    └─ SLSA provenance           │     └─ Policy gates               └─ Dependabot   │
│                                 │                                                      │
│                                 ├── CC7.1 ─────────────────────── Cap. V             │
│                                 │   (Monitoring)                  (Continuidad)       │
│                                 │     ├─ VPC Flow Logs               ├─ Flow Logs   │
│                                 │     ├─ SARIF reports               ├─ SARIF       │
│                                 │     └─ GitHub Security tab         └─ Monitoring  │
│                                 │                                                      │
│                                 └── CC7.2 ─────────────────────────────────────────  │
│                                     (Incident Response)                               │
│                                       └─ SBOM for impact analysis                     │
│                                                                                        │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Policy ID Quick Reference

### Secrets (gitleaks)

| Policy ID | Pattern | Example Match |
|-----------|---------|---------------|
| `efex-spei-token` | `spei_prod_tk_*` | `spei_prod_tk_abc123` |
| `efex-clabe` | `\b[0-9]{18}\b` | `646180123456789012` |
| `efex-database-password` | `efex_prod_password*` | `efex_prod_password_2024` |
| `stripe-api-key` | `sk_live_*` | `sk_live_51Nx...` |
| `aws-secret-access-key` | AWS key pattern | `wJalrXUtn...` |

### SAST (Semgrep)

| Policy ID | CWE | OWASP |
|-----------|-----|-------|
| `efex-sql-injection-transfer` | CWE-89 | A03:2021 |
| `efex-command-injection-subprocess` | CWE-78 | A03:2021 |
| `efex-unsafe-yaml-load` | CWE-502 | A08:2021 |
| `efex-sensitive-data-logging` | CWE-532 | A09:2021 |
| `efex-debug-enabled` | CWE-489 | A05:2021 |
| `efex-weak-crypto-md5` | CWE-327 | A02:2021 |
| `efex-hardcoded-spei-token` | CWE-798 | A07:2021 |

### IaC - S3 (Checkov + OPA)

| Policy ID | Description | Severity |
|-----------|-------------|----------|
| `CKV_AWS_19` | S3 encryption | HIGH |
| `CKV_AWS_20` | S3 block public access | CRITICAL |
| `CKV_AWS_21` | S3 versioning | MEDIUM |
| `EFEX-TF-S3-001` | KMS encryption required | HIGH |
| `EFEX-TF-S3-002` | Public access blocked | CRITICAL |
| `EFEX-TF-S3-003` | No public ACL | CRITICAL |
| `EFEX-TF-S3-004` | Versioning for sensitive | MEDIUM |

### IaC - IAM (Checkov + OPA)

| Policy ID | Description | Severity |
|-----------|-------------|----------|
| `CKV_AWS_1` | No Action:* | CRITICAL |
| `CKV_AWS_49` | No Resource:* | HIGH |
| `EFEX-TF-IAM-001` | Prohibit Action:* | CRITICAL |
| `EFEX-TF-IAM-002` | Prohibit Resource:* | HIGH |
| `EFEX-TF-IAM-003` | No full service access | CRITICAL |
| `EFEX-TF-IAM-004` | Restricted trust policy | CRITICAL |
| `EFEX-TF-IAM-005` | Warn on broad permissions | MEDIUM |

### IaC - Network (OPA)

| Policy ID | Description | Severity |
|-----------|-------------|----------|
| `CKV_AWS_23` | No 0.0.0.0/0 in SG | CRITICAL |
| `EFEX-TF-NET-001` | No public sensitive ports | CRITICAL |
| `EFEX-TF-NET-002` | No public SSH | CRITICAL |
| `EFEX-TF-NET-003` | No public database ports | CRITICAL |
| `EFEX-TF-NET-004` | No all-ports open | HIGH |
| `EFEX-TF-NET-005` | VPC flow logs required | MEDIUM |

### IaC - Database (Checkov + OPA)

| Policy ID | Description | Severity |
|-----------|-------------|----------|
| `CKV_AWS_16` | RDS encryption | CRITICAL |
| `CKV_AWS_17` | RDS not public | CRITICAL |
| `EFEX-TF-DB-001` | Storage encryption | CRITICAL |
| `EFEX-TF-DB-002` | Not publicly accessible | CRITICAL |
| `EFEX-TF-DB-003` | Deletion protection (prod) | HIGH |
| `EFEX-TF-DB-004` | Backup retention >= 7 | HIGH |
| `EFEX-TF-DB-005` | Performance insights | LOW |

### Container (Trivy + OPA)

| Policy ID | Description | Severity |
|-----------|-------------|----------|
| `DS002` | Running as root | HIGH |
| `DS026` | No HEALTHCHECK | MEDIUM |
| `EFEX-DOCKER-001` | Non-root USER required | CRITICAL |
| `EFEX-DOCKER-002` | Base image pinning | HIGH |
| `EFEX-DOCKER-003` | HEALTHCHECK required | MEDIUM |
| `EFEX-DOCKER-004` | COPY over ADD | MEDIUM |
| `EFEX-DOCKER-005` | No unnecessary packages | LOW |
| `EFEX-DOCKER-007` | No secrets in ENV | CRITICAL |

---

## Evidence File Mapping

| File | Contents | Size Est. | Retention |
|------|----------|-----------|-----------|
| `gitleaks.sarif` | Secret scan results | ~10KB | 90 days |
| `semgrep.sarif` | SAST results | ~50KB | 90 days |
| `trivy-sca.sarif` | Dependency CVEs | ~100KB | 90 days |
| `trivy-container.sarif` | Image scan results | ~200KB | 90 days |
| `checkov-results.sarif` | IaC scan results | ~150KB | 90 days |
| `conftest-results.json` | OPA policy results | ~20KB | 90 days |
| `sbom.spdx.json` | SPDX SBOM | ~500KB | 1 year |
| `sbom.cdx.json` | CycloneDX SBOM | ~400KB | 1 year |
| `hadolint.sarif` | Dockerfile lint | ~5KB | 90 days |
