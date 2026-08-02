# EFEX Secure Software Factory - Regulatory Compliance Mapping

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0 |
| Date | 2024-01-15 |
| Classification | Internal - Audit Ready |
| Applicable Regulations | CNBV/IFPE, Banxico, SOC 2 Type II, LFPDPPP |

---

## 1. Regulatory Framework Overview

### 1.1 Applicable Regulations for EFEX

| Regulation | Authority | Scope | Status |
|------------|-----------|-------|--------|
| **IFPE Authorization** | CNBV | Payment institution operations | In Progress |
| **Circular Única de Bancos (CUB)** | CNBV | Banking operations security | Applicable |
| **Circular 4/2021** | Banxico | Operational resilience | Applicable |
| **SOC 2 Type II** | AICPA | Trust services criteria | In Progress |
| **LFPDPPP** | INAI | Personal data protection | Applicable |
| **PCI-DSS** | PCI Council | Card data (future) | Planned |

### 1.2 Key Regulatory Articles

#### CNBV - Circular Única de Bancos (CUB)

| Article | Title | Relevance |
|---------|-------|-----------|
| **Art. 316 Bis** | Seguridad de la Información | Secrets management, access control |
| **Art. 316 Bis 17** | Cifrado de Información | Encryption at rest and transit |
| **Art. 316 Bis 18** | Control de Acceso | IAM, least privilege |
| **Art. 316 Bis 19** | Gestión de Vulnerabilidades | SAST, SCA, patching |
| **Anexo 1-A** | Requerimientos Tecnológicos | Infrastructure security |
| **Anexo 1-B** | Continuidad del Negocio | Backup, DR |

#### Banxico - Circular 4/2021

| Section | Requirement | Relevance |
|---------|-------------|-----------|
| **Capítulo III** | Gestión de Riesgos Tecnológicos | Risk assessment |
| **Capítulo IV** | Seguridad de la Información | Security controls |
| **Capítulo V** | Continuidad Operativa | Resilience |
| **Capítulo VI** | Proveedores de Servicios | Supply chain |

#### SOC 2 Trust Services Criteria

| Category | ID | Description |
|----------|-----|-------------|
| **Security** | CC6.1 | Logical and physical access |
| | CC6.2 | Authentication mechanisms |
| | CC6.3 | Access authorization |
| | CC6.6 | System operations security |
| | CC6.7 | Change management |
| | CC6.8 | Malicious software prevention |
| **Availability** | CC7.1 | System monitoring |
| | CC7.2 | Incident response |
| **Confidentiality** | CC8.1 | Confidential information protection |

---

## 2. Control-to-Regulation Matrix

### 2.1 Secrets Management

| Control | Implementation | CNBV | Banxico | SOC 2 |
|---------|----------------|------|---------|-------|
| No hardcoded secrets | gitleaks scan | Art. 316 Bis | Cap. IV | CC6.1 |
| Secrets in Secrets Manager | AWS Secrets Manager | Art. 316 Bis 18 | Cap. IV | CC6.1 |
| Secret rotation | Automated rotation | Art. 316 Bis | Cap. IV | CC6.2 |
| Audit trail for secret access | CloudTrail | Art. 316 Bis | Cap. IV | CC7.1 |

**Pipeline Evidence:**
```
Tool: gitleaks
Config: .gitleaks.toml
Output: evidence/red/gitleaks.sarif
Policy IDs: efex-spei-token, efex-database-password, stripe-api-key
```

### 2.2 Application Security (SAST)

| Control | Implementation | CNBV | Banxico | SOC 2 |
|---------|----------------|------|---------|-------|
| SQL injection prevention | Semgrep rule | Art. 316 Bis 19 | Cap. IV | CC6.6 |
| Command injection prevention | Semgrep rule | Art. 316 Bis 19 | Cap. IV | CC6.6 |
| Secure deserialization | Semgrep rule | Art. 316 Bis 19 | Cap. IV | CC6.6 |
| Input validation | Semgrep + Pydantic | Anexo 1-A | Cap. IV | CC6.6 |

**Pipeline Evidence:**
```
Tool: Semgrep
Config: .semgrep/efex-rules.yml + p/python + p/owasp-top-ten
Output: evidence/red/semgrep.sarif
Policy IDs: efex-sql-injection-transfer, efex-command-injection, efex-unsafe-yaml-load
```

### 2.3 Dependency Security (SCA)

| Control | Implementation | CNBV | Banxico | SOC 2 |
|---------|----------------|------|---------|-------|
| CVE scanning | Trivy | Art. 316 Bis 19 | Cap. IV | CC7.1 |
| License compliance | Syft SBOM | - | Cap. VI | CC6.6 |
| Dependency updates | Dependabot | Art. 316 Bis 19 | Cap. IV | CC6.7 |
| Approved dependencies | requirements.txt pinning | Anexo 1-A | Cap. VI | CC6.6 |

**Pipeline Evidence:**
```
Tool: Trivy
Config: --severity HIGH,CRITICAL --exit-code 1
Output: evidence/red/trivy-sca.sarif
CVEs Detected: CVE-2020-14343, CVE-2023-37920, CVE-2023-32681
```

### 2.4 Infrastructure Security (IaC)

| Control | Implementation | CNBV | Banxico | SOC 2 |
|---------|----------------|------|---------|-------|
| S3 encryption | Checkov CKV_AWS_19 | Art. 316 Bis 17 | Cap. IV | CC6.1 |
| S3 public access blocked | Checkov CKV_AWS_20 | Art. 316 Bis | Cap. IV | CC6.1 |
| IAM least privilege | OPA EFEX-TF-IAM-* | Art. 316 Bis 18 | Cap. IV | CC6.3 |
| Network segmentation | OPA EFEX-TF-NET-* | Anexo 1-A | Cap. IV | CC6.6 |
| RDS encryption | Checkov CKV_AWS_16 | Art. 316 Bis 17 | Cap. IV | CC6.1 |
| RDS private | Checkov CKV_AWS_17 | Anexo 1-A | Cap. IV | CC6.6 |
| VPC flow logs | OPA EFEX-TF-NET-005 | Art. 316 Bis | Cap. IV | CC7.1 |

**Pipeline Evidence:**
```
Tools: Checkov + Conftest (OPA)
Configs: policy/checkov/*.py, policy/terraform/*.rego
Output: evidence/red/checkov-results.sarif, conftest-results.json
Policy IDs: EFEX_AWS_001-005, EFEX-TF-S3-*, EFEX-TF-IAM-*, EFEX-TF-NET-*, EFEX-TF-DB-*
```

### 2.5 Container Security

| Control | Implementation | CNBV | Banxico | SOC 2 |
|---------|----------------|------|---------|-------|
| Non-root user | Trivy DS002 | Art. 316 Bis 18 | Cap. IV | CC6.8 |
| Image scanning | Trivy | Art. 316 Bis 19 | Cap. IV | CC6.8 |
| Base image pinning | OPA EFEX-DOCKER-002 | Anexo 1-A | Cap. VI | CC6.6 |
| No secrets in image | OPA EFEX-DOCKER-007 | Art. 316 Bis | Cap. IV | CC6.1 |
| Health checks | Trivy DS026 | Anexo 1-B | Cap. V | CC7.1 |

**Pipeline Evidence:**
```
Tools: Trivy + Hadolint + OPA
Configs: policy/docker/dockerfile.rego
Output: evidence/red/trivy-container.sarif, hadolint.sarif
Policy IDs: EFEX-DOCKER-001 to EFEX-DOCKER-008
```

### 2.6 Supply Chain Security

| Control | Implementation | CNBV | Banxico | SOC 2 |
|---------|----------------|------|---------|-------|
| SBOM generation | Syft | - | Cap. VI | CC7.2 |
| Artifact signing | cosign | Anexo 1-A | Cap. VI | CC6.7 |
| Provenance attestation | SLSA | Anexo 1-A | Cap. VI | CC6.7 |
| Signature verification | cosign verify | Anexo 1-A | Cap. VI | CC6.6 |

**Pipeline Evidence:**
```
Tools: Syft + cosign
Output: sbom.spdx.json, sbom.cdx.json, cosign signatures in registry
Attestations: SBOM as in-toto predicate
```

---

## 3. CNBV/IFPE Detailed Mapping

### 3.1 Artículo 316 Bis - Seguridad de la Información

> "Las instituciones deberán contar con políticas y procedimientos para la gestión de la seguridad de la información..."

| Requirement | Pipeline Control | Evidence |
|-------------|------------------|----------|
| Identificación de activos | SBOM generation | sbom.spdx.json |
| Clasificación de información | Terraform tags | remediated/infra/main.tf (DataClass tags) |
| Control de acceso | IAM policies scan | Checkov CKV_AWS_1 |
| Gestión de secretos | gitleaks | gitleaks.sarif |
| Registro de eventos | VPC flow logs, CloudTrail | OPA EFEX-TF-NET-005 |

### 3.2 Artículo 316 Bis 17 - Cifrado

> "La información sensible deberá estar cifrada tanto en tránsito como en reposo..."

| Requirement | Pipeline Control | Evidence |
|-------------|------------------|----------|
| Cifrado en reposo (S3) | Checkov CKV_AWS_19 | checkov-results.sarif |
| Cifrado en reposo (RDS) | Checkov CKV_AWS_16 | checkov-results.sarif |
| Cifrado en reposo (Logs) | OPA policy | EFEX-TF-DB-* |
| KMS key management | Terraform validation | remediated/infra/main.tf |
| Cifrado en tránsito | HTTPS enforcement | Security group rules |

### 3.3 Artículo 316 Bis 18 - Control de Acceso

> "Principio de mínimo privilegio en el acceso a sistemas y datos..."

| Requirement | Pipeline Control | Evidence |
|-------------|------------------|----------|
| Prohibir IAM Action:* | OPA EFEX-TF-IAM-001 | conftest-results.json |
| Prohibir IAM Resource:* | OPA EFEX-TF-IAM-002 | conftest-results.json |
| Trust policies restrictivas | OPA EFEX-TF-IAM-004 | conftest-results.json |
| Contenedores non-root | Trivy DS002 | trivy-container.sarif |
| Segregación de ambientes | Terraform workspace | remediated/infra/providers.tf |

### 3.4 Artículo 316 Bis 19 - Gestión de Vulnerabilidades

> "Proceso continuo de identificación, evaluación y remediación de vulnerabilidades..."

| Requirement | Pipeline Control | Evidence |
|-------------|------------------|----------|
| Escaneo de código | Semgrep SAST | semgrep.sarif |
| Escaneo de dependencias | Trivy SCA | trivy-sca.sarif |
| Escaneo de contenedores | Trivy image | trivy-container.sarif |
| Escaneo de infraestructura | Checkov IaC | checkov-results.sarif |
| Priorización por severidad | CRITICAL/HIGH exit-code | Pipeline configuration |
| SLA de remediación | Policy-as-Code gates | ADR-002 |

### 3.5 Anexo 1-A - Requerimientos Tecnológicos

| Section | Requirement | Pipeline Control |
|---------|-------------|------------------|
| **Desarrollo Seguro** | SDLC con seguridad embebida | Shift-left pipeline |
| | Revisión de código | Semgrep + policy gates |
| | Pruebas de seguridad | SAST/SCA/IaC scanning |
| **Infraestructura** | Segmentación de red | OPA network policies |
| | Hardening de sistemas | Container scanning |
| | Monitoreo de seguridad | VPC flow logs policy |
| **Gestión de Cambios** | Control de versiones | Git + signed commits |
| | Aprobación de cambios | PR approval + gates |
| | Trazabilidad | SARIF + SBOM |

---

## 4. SOC 2 Detailed Mapping

### 4.1 CC6 - Logical and Physical Access Controls

| Criteria | Description | Pipeline Control | Evidence |
|----------|-------------|------------------|----------|
| CC6.1 | Logical access security | gitleaks, IAM policies | Secrets scan, Checkov |
| CC6.2 | Authentication | IAM trust policies | OPA EFEX-TF-IAM-004 |
| CC6.3 | Access authorization | Least privilege | OPA EFEX-TF-IAM-001/002 |
| CC6.6 | System operations | SAST, network policies | Semgrep, OPA network |
| CC6.7 | Change management | Signed artifacts, gates | cosign, policy gates |
| CC6.8 | Malicious software | Container scanning | Trivy, non-root |

### 4.2 CC7 - System Operations

| Criteria | Description | Pipeline Control | Evidence |
|----------|-------------|------------------|----------|
| CC7.1 | Monitoring | VPC flow logs, logging | OPA policies, CloudWatch |
| CC7.2 | Incident response | SBOM for impact analysis | Syft SBOM |

### 4.3 SOC 2 Evidence Artifacts

| Artifact | Location | CC Mapping |
|----------|----------|------------|
| SARIF reports | evidence/*.sarif | CC6.6, CC7.1 |
| SBOM | evidence/sbom.*.json | CC7.2 |
| Pipeline logs | GitHub Actions logs | CC6.7 |
| Policy definitions | policy/**/*.rego | CC6.1, CC6.3 |
| ADRs | docs/adr/*.md | CC6.7 |
| Threat model | docs/THREAT-MODEL.md | CC6.6 |

---

## 5. Banxico Circular 4/2021 Mapping

### 5.1 Capítulo IV - Seguridad de la Información

| Article | Requirement | Pipeline Control |
|---------|-------------|------------------|
| 4.1 | Política de seguridad | ADRs + policy-as-code |
| 4.2 | Clasificación de información | Terraform tags |
| 4.3 | Control de acceso | IAM policies, Checkov |
| 4.4 | Cifrado | S3/RDS encryption policies |
| 4.5 | Gestión de vulnerabilidades | SAST/SCA/IaC pipeline |
| 4.6 | Monitoreo y detección | VPC flow logs, SARIF |

### 5.2 Capítulo VI - Proveedores de Servicios

| Article | Requirement | Pipeline Control |
|---------|-------------|------------------|
| 6.1 | Evaluación de proveedores | SBOM for dependency tracking |
| 6.2 | Gestión de riesgos | CVE scanning, severity gates |
| 6.3 | Monitoreo continuo | Dependabot, Trivy |

---

## 6. LFPDPPP - Data Protection Mapping

### 6.1 Personal Data Protection Principles

| Principle | Requirement | Pipeline Control |
|-----------|-------------|------------------|
| **Confidencialidad** | Protect PII from unauthorized access | S3 encryption, private access |
| **Seguridad** | Technical measures to protect data | All security layers |
| **Información** | Data inventory | SBOM, Terraform tags |

### 6.2 Specific Controls for KYC Data

| Data Type | Storage | Protection | Pipeline Validation |
|-----------|---------|------------|---------------------|
| INE/ID images | S3 | KMS encryption, blocked public | CKV_AWS_19, CKV_AWS_20 |
| CLABE numbers | RDS | Encrypted, private subnet | CKV_AWS_16, CKV_AWS_17 |
| RFC | RDS | Encrypted | CKV_AWS_16 |
| Address proof | S3 | KMS encryption | CKV_AWS_19 |

---

## 7. Audit-Ready Evidence Package

### 7.1 Evidence Checklist for Auditors

| # | Evidence Type | Location | Regulation |
|---|---------------|----------|------------|
| 1 | Security scan results (SARIF) | evidence/red/*.sarif | CNBV 316 Bis 19 |
| 2 | Remediation evidence | evidence/green/*.sarif | CNBV 316 Bis 19 |
| 3 | SBOM (SPDX format) | evidence/sbom.spdx.json | Banxico Cap. VI |
| 4 | SBOM (CycloneDX format) | evidence/sbom.cdx.json | Banxico Cap. VI |
| 5 | Policy definitions | policy/**/* | SOC 2 CC6.1 |
| 6 | Architecture decisions | docs/adr/*.md | SOC 2 CC6.7 |
| 7 | Threat model | docs/THREAT-MODEL.md | CNBV Anexo 1-A |
| 8 | Pipeline configuration | .github/workflows/*.yml | SOC 2 CC6.7 |
| 9 | CI/CD execution logs | GitHub Actions logs | SOC 2 CC7.1 |
| 10 | Artifact signatures | Container registry | CNBV Anexo 1-A |

### 7.2 Audit Questions & Answers

| Question | Answer | Evidence |
|----------|--------|----------|
| "¿Cómo previenen SQL injection?" | Semgrep SAST con regla efex-sql-injection-transfer bloquea builds | semgrep.sarif |
| "¿Cómo aseguran que S3 esté cifrado?" | Checkov CKV_AWS_19 + OPA EFEX-TF-S3-001 fallan build si falta cifrado | checkov-results.sarif |
| "¿Cómo controlan dependencias vulnerables?" | Trivy SCA con exit-code 1 en HIGH/CRITICAL | trivy-sca.sarif |
| "¿Cómo evitan secretos en código?" | gitleaks en cada commit con patrones EFEX custom | gitleaks.sarif |
| "¿Cómo aplican mínimo privilegio?" | OPA EFEX-TF-IAM-001/002 prohíben Action:*/Resource:* | conftest-results.json |
| "¿Qué hay en sus contenedores?" | SBOM generado con Syft en cada build | sbom.spdx.json |
| "¿Cómo verifican integridad de artefactos?" | cosign firma todas las imágenes con Sigstore | Rekor transparency log |

---

## 8. Compliance Dashboard Metrics

### 8.1 Key Metrics to Track

| Metric | Target | Current | Source |
|--------|--------|---------|--------|
| SAST findings (HIGH+) | 0 | - | Semgrep |
| SCA CVEs (CRITICAL) | 0 | - | Trivy |
| IaC failures | 0 | - | Checkov |
| Mean time to remediate (CRITICAL) | <24h | - | GitHub Issues |
| Policy gate pass rate | >95% | - | GitHub Actions |
| SBOM coverage | 100% | - | Syft |

### 8.2 Reporting Frequency

| Report | Frequency | Audience | Content |
|--------|-----------|----------|---------|
| Security scan summary | Per build | Dev teams | Pass/fail, findings count |
| Weekly vulnerability report | Weekly | Security team | New CVEs, remediation status |
| Monthly compliance report | Monthly | CISO, Compliance | Regulatory mapping, metrics |
| Quarterly audit package | Quarterly | Auditors | Full evidence package |

---

## Appendix A: Regulatory Reference Links

| Regulation | URL |
|------------|-----|
| CNBV CUB | https://www.cnbv.gob.mx/Normatividad/ |
| Banxico Circular 4/2021 | https://www.banxico.org.mx/marco-normativo/ |
| SOC 2 TSC | https://www.aicpa.org/soc2 |
| LFPDPPP | https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf |
| OWASP Top 10 | https://owasp.org/Top10/ |
| CIS Benchmarks | https://www.cisecurity.org/cis-benchmarks |

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| CNBV | Comisión Nacional Bancaria y de Valores |
| IFPE | Institución de Fondos de Pago Electrónico |
| CUB | Circular Única de Bancos |
| SPEI | Sistema de Pagos Electrónicos Interbancarios |
| CLABE | Clave Bancaria Estandarizada |
| LFPDPPP | Ley Federal de Protección de Datos Personales |
| SARIF | Static Analysis Results Interchange Format |
| SBOM | Software Bill of Materials |
| SAST | Static Application Security Testing |
| SCA | Software Composition Analysis |
| IaC | Infrastructure as Code |
