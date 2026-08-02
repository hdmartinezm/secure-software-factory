# ADR-004: GitHub Actions Supply Chain Hardening

## Status
**Accepted**

## Date
2025-08-01

## Context

GitHub Actions workflows are a critical part of our supply chain. They have access to:
- Repository secrets (API tokens, signing keys)
- Package registry credentials (GHCR)
- OIDC tokens for keyless signing

Supply chain attacks on CI/CD systems are increasingly common:
- **Codecov Bash Uploader (2021)**: Malicious script exfiltrated CI environment variables
- **ua-parser-js (2021)**: NPM package compromise affected build systems
- **GitHub Actions tag mutable attack vector**: `@v4` tags can be force-pushed

Our previous workflow used mutable references:
```yaml
uses: aquasecurity/trivy-action@master  # Mutable - security risk
uses: actions/checkout@v4               # Tag can be force-pushed
```

## Decision

### 1. Pin All GitHub Actions to Immutable SHA Commits

All third-party actions are pinned to specific commit SHAs:

```yaml
# Before (mutable)
uses: actions/checkout@v4

# After (immutable)
uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332 # v4.1.7
```

**Actions pinned:**

| Action | SHA | Version |
|--------|-----|---------|
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | v4 |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | v4 |
| `actions/setup-python` | `a26af69be951a213d495a4c3e4e4022e16d87065` | v5 |
| `github/codeql-action/upload-sarif` | `47be0dbd5113ab1b79fe2dd3f68bdf7e426cdc87` | v3 |
| `aquasecurity/trivy-action` | `c07df6fec6fa692e6fd1200d50aaa1fdd66f03c8` | master |
| `hashicorp/setup-terraform` | `b9cd54a3c349d3f38e8881555d616ced269862dd` | v3 |
| `bridgecrewio/checkov-action` | `7b972723c44fb3d256283fac96fae5d7c1894bb7` | v12 |
| `hadolint/hadolint-action` | `54c9adbab1582c2ef04b2016b760714a4bfde3cf` | v3.1.0 |
| `docker/setup-buildx-action` | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` | v3 |
| `docker/login-action` | `c94ce9fb468520275223c153574b00df6fe4bcc9` | v3 |
| `docker/metadata-action` | `c299e40c65443455700f0fdfc63efafe5b349051` | v5 |
| `docker/build-push-action` | `10e90e3645eae34f1e60eeb005ba3a3d33f178e8` | v6 |
| `anchore/sbom-action` | `e22c389904149dbc22b58101806040fa8d37a610` | v0 |
| `sigstore/cosign-installer` | `f713795cb21599bc4e5c4b58cbad1da852d7eeb9` | v3 |

### 2. Apply Least Privilege Permissions

**Global default (workflow level):**
```yaml
permissions:
  contents: read
```

**Job-level expansion only where needed:**
```yaml
# Security scanning jobs
permissions:
  contents: read
  security-events: write  # For SARIF upload to GitHub Security tab

# SBOM & Signing job
permissions:
  contents: read
  packages: write     # Push to GHCR
  id-token: write     # OIDC token for keyless signing
```

### 3. Clarify SLSA Compliance Claims

Previous workflow claimed "SLSA Level 2" but didn't use the official provenance generator.

**Updated claim:**
```yaml
# Control: Supply Chain Security, SLSA-aligned controls
#
# Note: This workflow implements SLSA-aligned supply chain controls including:
#   - Keyless signing (Sigstore/Fulcio OIDC)
#   - SBOM generation (SPDX + CycloneDX)
#   - SBOM attestation
# For full SLSA Level 2+ provenance, consider adding:
#   - slsa-framework/slsa-github-generator
```

## Rationale

### Why SHA Pinning Over Tags?

| Approach | Security | Maintainability | Risk |
|----------|----------|-----------------|------|
| `@master` | None | Auto-updates | Tag compromise, breaking changes |
| `@v4` | Low | Auto-updates (major) | Force-push attack |
| `@v4.1.7` | Medium | Manual updates | Tag deletion/re-creation |
| `@sha256:abc...` | High | Manual updates | None |

SHA pinning is the only approach that provides **immutability guarantees**.

### Why Least Privilege?

A compromised or malicious action with excessive permissions could:
- **`contents: write`**: Modify repository code, inject backdoors
- **`packages: write`**: Push malicious container images
- **`id-token: write`**: Sign malicious artifacts as legitimate

By defaulting to `contents: read` and expanding only where needed, we limit blast radius.

### Why Clarify SLSA Claims?

SLSA levels have specific requirements:
- **Level 1**: Build process documented
- **Level 2**: Signed provenance, hosted build service
- **Level 3**: Hardened build environment, isolated

Without `slsa-github-generator`, we can't claim formal SLSA Level 2 provenance. Using "SLSA-aligned" is accurate and avoids misrepresentation.

## Consequences

### Positive
- **Immutability**: Actions cannot be modified after pinning
- **Auditability**: Exact action version in every build
- **Defense in depth**: Multiple supply chain controls
- **Honest claims**: Accurate representation of security posture

### Negative
- **Maintenance burden**: SHA updates require manual workflow changes
- **Update process**: Need Dependabot or renovate for action updates

### Mitigations
- Configure Dependabot for GitHub Actions updates:
  ```yaml
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
  ```
- Document SHA update process in CONTRIBUTING.md

## Compliance Mapping

| Control | Requirement | Implementation |
|---------|-------------|----------------|
| SOC 2 CC6.1 | Logical access controls | Least privilege permissions |
| SOC 2 CC6.6 | Change management | SHA pinning prevents unauthorized changes |
| SLSA Build L2 | Hosted, authenticated build | GitHub Actions + OIDC |
| CIS Supply Chain | Dependency pinning | All actions pinned to SHA |

## References

- [GitHub Security Hardening](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions)
- [SLSA Requirements](https://slsa.dev/spec/v1.0/requirements)
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner)
- [Pinning GitHub Actions](https://michaelheap.com/github-actions-pin-versions/)
