# EFEX Secure Software Factory - RED Scenario Evidence

## Pipeline Run Details

| Field | Value |
|-------|-------|
| **Run ID** | 30568251569 |
| **Conclusion** | FAILURE |
| **Date** | 2026-07-30T17:57:06Z |
| **Branch** | main (initial push with vulnerable code) |
| **URL** | https://github.com/hdmartinezm/secure-software-factory/actions/runs/30568251569 |

## Security Checks Results

| Check | Status | Duration | Failure Reason |
|-------|--------|----------|----------------|
| 🔐 Secrets Detection | FAILED | 51s | Hardcoded secrets detected (Gitleaks) |
| 🔍 SAST Analysis | SUCCESS | 49s | - |
| 📦 Dependency Scan (SCA) | FAILED | 1m6s | HIGH/CRITICAL CVEs in dependencies |
| 🏗️ IaC Security Scan | FAILED | 1m12s | Multiple Checkov policy violations |
| 🐳 Container Security | FAILED | 1m33s | Dockerfile runs as root |
| 🚦 Security Gate | FAILED | 4s | Upstream checks failed |
| 📋 SBOM & Signing | SKIPPED | - | Security gate blocked |

## Detailed Findings

### 1. Secrets Detection (Gitleaks)
```
🛑 Leaks detected, see job summary for details
```
- Hardcoded database passwords
- API keys in source code
- Stripe keys exposed

### 2. IaC Security (Checkov)
```
CKV_AWS_62: Ensure IAM policies that allow full "*-*" administrative privileges are not created
CKV_AWS_63: Ensure no IAM policies documents allow "*" as a statement's actions
CKV_AWS_289: Ensure IAM policies does not allow permissions management / resource exposure without constraints
CKV_AWS_290: Ensure IAM policies does not allow write access without constraints
CKV_AWS_53: Ensure S3 bucket has block public ACLS enabled
CKV_AWS_54: Ensure S3 bucket has block public policy enabled
CKV_AWS_55: Ensure S3 bucket has ignore public ACLs enabled
CKV_AWS_56: Ensure S3 bucket has 'restrict_public_buckets' enabled
EFEX_AWS_001: Ensure S3 bucket has encryption enabled (EFEX-CNBV)
```

### 3. Container Security
```
EFEX-SEC-004: Dockerfile must specify a non-root USER directive
Add 'USER 1000:1000' before CMD instruction
```

### 4. Security Gate
```
Security Gate FAILED - One or more security checks did not pass
```

## Job URLs

- Secrets: https://github.com/hdmartinezm/secure-software-factory/actions/runs/30568251569/job/90958072745
- IaC: https://github.com/hdmartinezm/secure-software-factory/actions/runs/30568251569/job/90958072765
- SCA: https://github.com/hdmartinezm/secure-software-factory/actions/runs/30568251569/job/90958072868
- Container: https://github.com/hdmartinezm/secure-software-factory/actions/runs/30568251569/job/90958072915
- Security Gate: https://github.com/hdmartinezm/secure-software-factory/actions/runs/30568251569/job/90958502067

## Conclusion

The pipeline correctly **BLOCKED** the vulnerable code from being deployed. This demonstrates that:

1. **Defense in Depth** - Multiple layers caught different vulnerabilities
2. **Fail-Fast** - Pipeline stopped at Security Gate, preventing build/deploy
3. **Policy Enforcement** - Custom EFEX policies (EFEX_AWS_001, EFEX-SEC-004) were enforced
4. **Compliance** - CNBV/SOC2 controls actively preventing non-compliant code
