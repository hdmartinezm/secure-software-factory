# ADR-001: Security Tooling Selection

## Status
**Accepted**

## Date
2024-01-15

## Context

EFEX requires a DevSecOps pipeline that:
1. Detects security issues before production (shift-left)
2. Provides auditable evidence for IFPE/CNBV and SOC 2 compliance
3. Maintains Lead Time < 1 hour for 25 engineers across 5 SWAT teams
4. Minimizes false positives to avoid developer friction

We evaluated tools for each security layer:

### Options Evaluated

| Layer | Options Evaluated |
|-------|-------------------|
| Secrets | gitleaks, truffleHog, git-secrets, GitHub Secret Scanning |
| SAST | Semgrep, Bandit, SonarQube, CodeQL, Snyk Code |
| SCA | Trivy, Snyk, Dependabot, OWASP Dependency-Check |
| IaC | Checkov, tfsec, Terrascan, OPA/Conftest |
| Container | Trivy, Snyk Container, Anchore, Clair |

## Decision

### Selected Stack

| Layer | Primary Tool | Rationale |
|-------|-------------|-----------|
| **Secrets** | gitleaks | OSS, custom rules via TOML, fast (<10s), low false positives |
| **SAST** | Semgrep | OSS, custom rules via YAML, excellent Python support, SARIF output |
| **SCA** | Trivy | OSS, unified tool (fs + container), fast, excellent CVE database |
| **IaC** | Checkov + Conftest | Checkov: 1000+ built-in checks; Conftest: custom OPA for EFEX policies |
| **Container** | Trivy | Reuse same tool as SCA, consistent reporting |
| **SBOM** | Syft | OSS, Anchore project, SPDX + CycloneDX formats |
| **Signing** | cosign | Sigstore project, keyless signing, SLSA attestations |

## Rationale

### gitleaks over alternatives

| Criterion | gitleaks | truffleHog | GitHub Secret Scanning |
|-----------|----------|------------|------------------------|
| OSS | ✅ | ✅ | ❌ (Enterprise only for push protection) |
| Custom patterns | ✅ TOML | ✅ Regex | ❌ Limited |
| CI integration | ✅ Native | ✅ | ✅ |
| Speed | <10s | ~30s | N/A |
| EFEX patterns (SPEI, CLABE) | ✅ Easy to add | ✅ | ❌ |

**Decision**: gitleaks provides the best balance of speed, customization, and OSS licensing.

### Semgrep over alternatives

| Criterion | Semgrep | Bandit | SonarQube | CodeQL |
|-----------|---------|--------|-----------|--------|
| OSS | ✅ | ✅ | ❌ Enterprise for full features | ✅ |
| Custom rules | ✅ YAML (simple) | ❌ Python (complex) | ✅ | ✅ (QL language) |
| Python support | Excellent | Excellent | Good | Excellent |
| Speed | ~30s | ~20s | >2min | >3min |
| False positive rate | Low | High | Medium | Low |
| SARIF output | ✅ | ❌ | ✅ | ✅ |

**Decision**: Semgrep offers simple custom rule creation (YAML), low false positives, and excellent Python/FastAPI coverage. Bandit has too many false positives for financial code.

### Trivy over alternatives

| Criterion | Trivy | Snyk | OWASP Dep-Check |
|-----------|-------|------|-----------------|
| OSS | ✅ | ❌ Freemium | ✅ |
| Unified (fs + container) | ✅ | ❌ Separate products | ❌ |
| Speed | Fast | Medium | Slow |
| CVE database freshness | Hourly | Real-time | Daily |
| SARIF output | ✅ | ✅ | ❌ |
| Ignore unfixed | ✅ | ✅ | ❌ |

**Decision**: Trivy provides a single tool for both SCA and container scanning, reducing complexity and ensuring consistent reporting.

### Checkov + Conftest for IaC

| Criterion | Checkov | tfsec | Terrascan | Conftest |
|-----------|---------|-------|-----------|----------|
| Built-in checks | 1000+ | 100+ | 500+ | 0 (policy only) |
| Custom checks | ✅ Python | ❌ | ✅ | ✅ Rego |
| Multi-framework | ✅ (TF, K8s, Helm, CF) | ❌ TF only | ✅ | ✅ |
| SARIF output | ✅ | ✅ | ✅ | ❌ |

**Decision**: Use Checkov for comprehensive built-in coverage with Python custom checks, and Conftest for EFEX-specific OPA policies that require business logic (e.g., "production S3 buckets must use KMS key alias/efex-*").

## Consequences

### Positive
- **100% OSS**: No vendor lock-in, no licensing costs for initial deployment
- **SARIF standardization**: All tools output SARIF for unified GitHub Security tab
- **Speed**: Total pipeline time ~3-5 minutes (within Lead Time budget)
- **Customization**: All tools support EFEX-specific rules
- **Auditability**: Evidence trail for IFPE/SOC 2 auditors

### Negative
- **Learning curve**: Team needs to learn Rego for OPA policies
- **Maintenance**: OSS tools require version management and updates
- **Coverage gaps**: Some edge cases may require additional tools later

### Mitigations
- **Rego learning**: Created policy templates with extensive comments
- **Version pinning**: All tools pinned in CI workflow
- **Future expansion**: Architecture supports adding Snyk/SonarQube if needed

## Compliance Mapping

| Tool | SOC 2 Control | CNBV/IFPE Control |
|------|---------------|-------------------|
| gitleaks | CC6.1 (Logical Access) | Art. 316 Bis (Secrets) |
| Semgrep | CC6.6 (System Operations) | Anexo 1-A (Vuln Management) |
| Trivy | CC7.1 (Monitoring) | Circular 4/2021 (Patching) |
| Checkov | CC6.1, CC6.3 (Access Control) | Art. 316 Bis 17 (Encryption) |
| Syft | CC7.2 (Incident Response) | Supply Chain Traceability |
| cosign | CC6.6 (Change Management) | Artifact Integrity |

## References

- [Semgrep Rules Registry](https://semgrep.dev/r)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [Checkov Policies](https://www.checkov.io/5.Policy%20Index/all.html)
- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
