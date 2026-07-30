# ADR-002: Policy-as-Code Strategy

## Status
**Accepted**

## Date
2024-01-15

## Context

EFEX operates under strict regulatory requirements (CNBV/IFPE, SOC 2) that mandate specific security controls. Traditional approaches rely on:
- Manual security reviews (slow, inconsistent)
- Documentation-based policies (unenforceable)
- Post-deployment audits (reactive, costly)

We need a Policy-as-Code (PaC) strategy that:
1. **Codifies** regulatory requirements into enforceable policies
2. **Automates** enforcement at build time (shift-left)
3. **Provides** audit evidence automatically
4. **Balances** security with developer velocity (Lead Time < 1h)

## Decision

### Policy-as-Code Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    POLICY-AS-CODE LAYERS                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Layer 1: VENDOR DEFAULTS                                       │
│  ├─ Checkov built-in (1000+ checks)                            │
│  ├─ Semgrep registry (OWASP, Python security)                  │
│  └─ Trivy vulnerability database                               │
│                                                                 │
│  Layer 2: EFEX CUSTOM POLICIES                                  │
│  ├─ OPA/Rego for Terraform (policy/terraform/*.rego)           │
│  ├─ Checkov Python checks (policy/checkov/*.py)                │
│  ├─ Semgrep YAML rules (.semgrep/efex-rules.yml)               │
│  └─ gitleaks TOML patterns (.gitleaks.toml)                    │
│                                                                 │
│  Layer 3: EXCEPTION MANAGEMENT                                  │
│  ├─ Inline suppressions (with justification + expiry)          │
│  ├─ Baseline files (known issues being remediated)             │
│  └─ Waiver workflow (approval + audit trail)                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Policy Severity Mapping

| Severity | Action | Regulatory Driver |
|----------|--------|-------------------|
| **CRITICAL** | Block build, no exceptions | CNBV Art. 316 Bis (data exposure) |
| **HIGH** | Block build, waiver possible | SOC 2 CC6.x controls |
| **MEDIUM** | Warn, track in backlog | Best practices |
| **LOW** | Informational | Recommendations |

### Custom Policy Categories

#### 1. EFEX-TF-* (Terraform/IaC)
22 custom OPA policies covering:
- S3 encryption and public access (CNBV Art. 316 Bis 17)
- IAM least privilege (SOC 2 CC6.3)
- Security group restrictions (SOC 2 CC6.6)
- RDS encryption and accessibility (CNBV encryption requirements)

#### 2. EFEX-SAST-* (Application Security)
10 custom Semgrep rules covering:
- SPEI/financial credential detection
- SQL injection in financial contexts
- Command injection
- Insecure deserialization
- Sensitive data logging

#### 3. EFEX-DOCKER-* (Container Security)
8 custom OPA policies covering:
- Non-root user enforcement
- Base image pinning
- Secret exposure in ENV/ARG

#### 4. EFEX_AWS_* (Checkov Custom)
5 custom Python checks for AWS-specific EFEX requirements.

### Gate Strategy: Gradual Enforcement

```
┌──────────────────────────────────────────────────────────────┐
│                 GRADUAL GATE ROLLOUT                         │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  Week 1: SHADOW MODE                                         │
│  ├─ All checks run                                           │
│  ├─ Results logged but don't block                          │
│  └─ Teams review findings, adjust suppressions               │
│                                                              │
│  Week 2: WARN ON PR                                          │
│  ├─ Checks run on PR creation                               │
│  ├─ Warnings displayed but merge allowed                    │
│  └─ Teams start fixing HIGH findings                        │
│                                                              │
│  Week 3: BLOCK CRITICAL                                      │
│  ├─ CRITICAL findings block merge                           │
│  ├─ HIGH findings warn                                       │
│  └─ Waiver process available                                │
│                                                              │
│  Week 4: FULL ENFORCEMENT                                    │
│  ├─ CRITICAL + HIGH block merge                             │
│  ├─ MEDIUM tracked in backlog                               │
│  └─ Waivers require security team approval                  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Exception Handling

#### Inline Suppression (Developer)
```python
# semgrep: ignore efex-sql-injection-transfer
# Reason: Input validated by Pydantic model with regex
# Approved: @security-team
# Expires: 2024-06-01
cursor.execute(f"SELECT * FROM audit_log WHERE id = '{validated_id}'")
```

```hcl
# checkov:skip=CKV_AWS_19:S3 encryption handled by org-level SCP
resource "aws_s3_bucket" "static_assets" {
  bucket = "efex-static-assets"
}
```

#### Baseline File (Team)
```yaml
# .semgrep-baseline.yml
# Known issues being tracked for remediation
baseline:
  - rule_id: efex-hardcoded-db-password
    path: legacy/config.py
    jira: EFEX-1234
    remediation_date: 2024-03-01
```

#### Waiver Workflow (Security Team)
```yaml
# .security-waivers.yml
waivers:
  - policy: EFEX-TF-IAM-002
    resource: aws_iam_policy.legacy_admin
    reason: "Legacy system migration in progress"
    approved_by: security@efex.com
    approved_date: 2024-01-10
    expires: 2024-04-01
    jira: EFEX-5678
```

## Rationale

### Why OPA/Rego for IaC Policies?

1. **Expressiveness**: Rego can express complex business logic (e.g., "production resources must use KMS keys with alias matching /efex-prod-*/")
2. **Testability**: OPA policies can have unit tests
3. **Ecosystem**: Conftest integrates with Terraform plan JSON
4. **Separation**: Policy definitions separate from tool configuration

### Why Not Just Use Checkov Defaults?

Checkov defaults are generic. EFEX needs:
- **CNBV-specific**: Mexican regulation requirements
- **Context-aware**: Different rules for prod vs. dev
- **Business logic**: S3 bucket naming conventions, IAM role prefixes

### Why Gradual Enforcement?

Immediate hard blocks would:
- Create developer frustration
- Generate waiver request floods
- Slow down the 5 SWAT teams
- Undermine security team credibility

Gradual rollout allows:
- Teams to understand policies
- Time to fix existing issues
- Trust building between security and development

## Consequences

### Positive
- **Automated enforcement**: No manual reviews for standard violations
- **Audit trail**: Every policy evaluation logged with timestamp
- **Developer self-service**: Clear error messages with fix guidance
- **Scalable**: 5 SWAT teams, same policies, no bottleneck

### Negative
- **Initial investment**: ~40 hours to write custom policies
- **Maintenance burden**: Policies need updates as regulations evolve
- **False positives**: Some custom rules may need tuning

### Mitigations
- **Policy testing**: Unit tests for all Rego policies
- **Feedback loop**: Monthly review of waiver requests
- **Documentation**: Every policy includes regulatory mapping

## Compliance Mapping

| Policy Category | SOC 2 Control | CNBV/IFPE Control |
|-----------------|---------------|-------------------|
| EFEX-TF-S3-* | CC6.1 | Art. 316 Bis 17 |
| EFEX-TF-IAM-* | CC6.3 | Principle of Least Privilege |
| EFEX-TF-NET-* | CC6.6 | Network Segmentation |
| EFEX-TF-DB-* | CC6.1, CC7.2 | Encryption at Rest |
| EFEX-SAST-* | CC6.6 | Vulnerability Management |
| EFEX-DOCKER-* | CC6.8 | Container Security |

## References

- [OPA Rego Language](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Checkov Custom Checks](https://www.checkov.io/3.Custom%20Policies/Custom%20Policies%20Overview.html)
- [CNBV Circular Única de Bancos](https://www.cnbv.gob.mx/)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/resources/article/soc-2-overview)
