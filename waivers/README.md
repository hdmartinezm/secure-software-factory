# Security Waivers

This directory contains approved security exceptions (waivers) for specific vulnerabilities.

## How Waivers Work

1. Developer identifies a false positive or accepted risk
2. Creates a waiver YAML file in this directory
3. Gets approval from security team (via PR review)
4. Pipeline validates waiver before allowing bypass

## Waiver Schema

```yaml
# waivers/<finding-id>.yaml
id: "EFEX-WAIVER-001"           # Unique waiver ID
finding_id: "CKV_AWS_145"       # The check/rule being waived
finding_pattern: ""              # Optional: regex pattern for file/line
owner: "platform-team"           # Team responsible
approved_by: "security@efex.com" # Approver email
ticket: "SEC-1234"               # Tracking ticket (Jira, Linear, etc.)
reason: "False positive - this S3 bucket is intentionally public for static assets"
risk_accepted: true              # Explicit risk acceptance
expiration: "2024-03-15"         # REQUIRED: Waiver expires on this date
created: "2024-01-15"            # When waiver was created
```

## Validation

The pipeline validates:
- Waiver file exists for the finding
- `expiration` date has not passed
- `approved_by` is a valid security team member
- `ticket` references a real tracking issue

## Expired Waivers

When a waiver expires:
1. Pipeline fails with clear message
2. Owner is notified via PR comment
3. Waiver must be renewed or vulnerability fixed
