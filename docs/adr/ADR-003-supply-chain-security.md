# ADR-003: Supply Chain Security Strategy

## Status
**Accepted**

## Date
2024-01-15

## Context

Software supply chain attacks have increased dramatically:
- **SolarWinds (2020)**: Compromised build system, 18,000 organizations affected
- **Codecov (2021)**: Malicious bash uploader in CI/CD
- **Log4Shell (2021)**: Critical CVE in ubiquitous logging library
- **ua-parser-js (2021)**: NPM package hijacking

As a fintech handling SPEI transactions and KYC data, EFEX is a high-value target. We need:
1. **Visibility**: Know what's in our software (SBOM)
2. **Integrity**: Prove artifacts haven't been tampered with (signatures)
3. **Provenance**: Prove where artifacts came from (attestations)
4. **Monitoring**: Continuous vulnerability tracking

## Decision

### Supply Chain Security Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 SUPPLY CHAIN SECURITY LAYERS                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  BUILD TIME                                                     │
│  ├─ Dependency scanning (Trivy)                                │
│  ├─ License compliance check                                    │
│  ├─ SBOM generation (Syft)                                     │
│  └─ Artifact signing (cosign)                                  │
│                                                                 │
│  RUNTIME                                                        │
│  ├─ Signature verification (cosign verify)                     │
│  ├─ SBOM attestation validation                                │
│  └─ Continuous monitoring (Dependabot/Snyk)                    │
│                                                                 │
│  GOVERNANCE                                                     │
│  ├─ Approved dependency list                                   │
│  ├─ SLSA Level 2 compliance                                    │
│  └─ Incident response playbook                                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Component Selection

| Component | Tool | Rationale |
|-----------|------|-----------|
| **SBOM Generation** | Syft | OSS, supports SPDX + CycloneDX, Anchore ecosystem |
| **Artifact Signing** | cosign (Sigstore) | Keyless signing, OIDC integration, OSS |
| **Attestations** | cosign attest | SLSA predicates, in-toto format |
| **Verification** | cosign verify | Validates signatures and attestations |
| **Continuous Monitoring** | Dependabot + Trivy | GitHub native + comprehensive CVE DB |

### SBOM Strategy

#### Formats Supported
- **SPDX 2.3**: ISO/IEC 5962:2021 standard, required by US Executive Order 14028
- **CycloneDX 1.4**: OWASP standard, better for vulnerability correlation

#### SBOM Contents
```json
{
  "spdxVersion": "SPDX-2.3",
  "name": "efex-transfer-service",
  "packages": [
    {
      "name": "fastapi",
      "versionInfo": "0.109.0",
      "supplier": "Organization: FastAPI",
      "checksums": [
        {
          "algorithm": "SHA256",
          "checksumValue": "abc123..."
        }
      ],
      "externalRefs": [
        {
          "referenceType": "purl",
          "referenceLocator": "pkg:pypi/fastapi@0.109.0"
        }
      ]
    }
  ]
}
```

### Signing Strategy

#### Keyless Signing with Sigstore
```yaml
# GitHub Actions workflow
- name: Sign container image
  env:
    COSIGN_EXPERIMENTAL: "true"
  run: |
    cosign sign --yes \
      ghcr.io/efex/api@${{ steps.build.outputs.digest }}
```

**Why Keyless?**
- No key management overhead
- Identity tied to OIDC (GitHub Actions identity)
- Transparency log (Rekor) provides audit trail
- Short-lived certificates (10 minutes)

#### What Gets Signed
1. **Container images**: Every image pushed to registry
2. **SBOM**: Attested as predicate on image
3. **Vulnerability scan results**: Optional attestation

### SLSA Compliance

**Target: SLSA Level 2**

| Requirement | Implementation |
|-------------|----------------|
| Version controlled | GitHub repository |
| Verified history | Branch protection rules |
| Retained indefinitely | GitHub retention policies |
| Two-person review | PR approval requirements |
| Hermetic builds | GitHub Actions hosted runners |
| Build service | GitHub Actions (not self-hosted) |
| Build as code | `.github/workflows/` |
| Ephemeral environment | Fresh runner per build |
| Provenance generated | SLSA GitHub Generator |

### Verification at Deployment

```bash
# Verify signature before deployment
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/efex/.*' \
  ghcr.io/efex/api@sha256:abc123...

# Verify SBOM attestation
cosign verify-attestation \
  --type spdxjson \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/efex/api@sha256:abc123...
```

### Continuous Monitoring

```yaml
# Dependabot configuration
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    labels:
      - "dependencies"
      - "security"
    reviewers:
      - "efex/security-team"
```

## Rationale

### Why Sigstore/cosign over GPG signing?

| Criterion | cosign (Sigstore) | GPG |
|-----------|-------------------|-----|
| Key management | Keyless (OIDC) | Manual key distribution |
| Transparency | Rekor log | None |
| Revocation | Certificate expiry | Complex CRL management |
| CI/CD integration | Native | Complex setup |
| Audit trail | Automatic | Manual |

### Why SPDX + CycloneDX (both)?

- **SPDX**: Regulatory compliance (NTIA minimum elements)
- **CycloneDX**: Better tooling for vulnerability correlation

Generating both takes <10 seconds and provides maximum compatibility.

### Why SLSA Level 2 (not Level 3)?

- **Level 2**: Achievable with GitHub Actions
- **Level 3**: Requires isolated build service (additional infrastructure)
- **Pragmatism**: Level 2 covers 90% of supply chain risks

## Consequences

### Positive
- **Audit trail**: Every artifact has verifiable provenance
- **Incident response**: SBOM enables rapid CVE impact assessment
- **Compliance**: Meets emerging SBOM regulations (US EO 14028)
- **Trust**: Customers can verify artifact integrity

### Negative
- **Build time**: +30 seconds for SBOM/signing
- **Complexity**: New concepts for development team
- **Storage**: SBOM artifacts increase storage requirements

### Mitigations
- **Parallelization**: SBOM/signing runs after tests pass
- **Documentation**: Training materials for team
- **Retention policy**: SBOMs retained for 90 days (configurable)

## Threat Model Integration

This ADR addresses the following supply chain threats:

| Threat | Mitigation |
|--------|------------|
| Malicious dependency | SCA scanning + approved list |
| Typosquatting | Package URL verification in SBOM |
| Compromised CI/CD | SLSA provenance, signed artifacts |
| Artifact tampering | cosign signatures |
| Unknown vulnerabilities | SBOM enables rapid scanning when CVE published |

## Compliance Mapping

| Control | Requirement | Implementation |
|---------|-------------|----------------|
| SOC 2 CC6.6 | Change management | Signed artifacts prove origin |
| SOC 2 CC7.1 | System monitoring | SBOM enables vulnerability tracking |
| CNBV | Software inventory | SBOM provides complete inventory |
| NTIA | SBOM minimum elements | SPDX 2.3 compliant |

## References

- [Sigstore Documentation](https://docs.sigstore.dev/)
- [SLSA Framework](https://slsa.dev/)
- [NTIA SBOM Minimum Elements](https://www.ntia.doc.gov/report/2021/minimum-elements-software-bill-materials-sbom)
- [SPDX Specification](https://spdx.github.io/spdx-spec/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
