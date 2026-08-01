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
| `actions/checkout` | `692973e3d937129bcbf40652eb9f2f61becf3332` | v4.1.7 |
| `actions/upload-artifact` | `834a144ee995460fba8ed112a2fc961b36a5ec5a` | v4.3.6 |
| `actions/setup-python` | `39cd14951b08e74b54015e9e001cdefcf80e669f` | v5.1.1 |
| `github/codeql-action/upload-sarif` | `2d790406f505036ef40ecba973cc774a50395aac` | v3.25.15 |
| `aquasecurity/trivy-action` | `6e7b7d1fd3e4fef0c7fa525c3e52f8d20efcecfd` | v0.24.0 |
| `hashicorp/setup-terraform` | `b9cd54a3c349d3c85f40e8e8e8e99c63c6cd8f10` | v3.1.1 |
| `bridgecrewio/checkov-action` | `d2b801c47f51b102c4de10b27ac2573b7e2d1c90` | v12.2.0 |
| `hadolint/hadolint-action` | `54c9adbab1582c2ef04b2c5c1b92b95c7b0e0b5e` | v3.1.0 |
| `docker/setup-buildx-action` | `988b5a0280414f521da01fcc63a27aeeb4b104db` | v3.6.1 |
| `docker/login-action` | `0d4c9c5ea7693da7b068278f7b52bda2a190a446` | v3.3.0 |
| `docker/metadata-action` | `8e5442c4ef9f78752691e2d8f8d19755c6f78e81` | v5.5.1 |
| `docker/build-push-action` | `16ebe778df0e7752d2cfcbd924afdbbd89c1a755` | v6.7.0 |
| `anchore/sbom-action` | `61119d458adab75f756bc0b9e4bde25725f86a7a` | v0.17.0 |
| `sigstore/cosign-installer` | `59acb6260d9c0ba8f4a2f9d9b48431a222b68e20` | v3.6.0 |

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
