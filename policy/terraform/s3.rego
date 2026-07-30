# EFEX Custom Policy: S3 Security
# ================================
# Policy ID: EFEX-TF-S3-*
# Regulatory Mapping: CNBV Art. 316 Bis 17, SOC 2 CC6.1
#
# These policies enforce encryption and access controls for S3 buckets
# containing sensitive financial data (KYC documents, transaction logs).

package terraform.s3

import future.keywords.in

# Helper: Get all S3 bucket resources from plan
s3_buckets[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket"
    resource.change.actions[_] != "delete"
}

# Helper: Get S3 bucket encryption configurations
s3_encryption_configs[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_server_side_encryption_configuration"
    resource.change.actions[_] != "delete"
}

# Helper: Get S3 public access blocks
s3_public_access_blocks[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    resource.change.actions[_] != "delete"
}

# =============================================================================
# EFEX-TF-S3-001: S3 buckets must have encryption at rest
# Severity: HIGH
# Regulation: CNBV Art. 316 Bis 17 - Cifrado de datos sensibles
# =============================================================================
deny[msg] {
    bucket := s3_buckets[_]
    bucket_name := bucket.change.after.bucket

    # Check if there's a corresponding encryption configuration
    not has_encryption_config(bucket_name)

    msg := sprintf(
        "EFEX-TF-S3-001: S3 bucket '%s' must have server-side encryption enabled. Required for CNBV Art. 316 Bis 17 compliance. Add aws_s3_bucket_server_side_encryption_configuration resource.",
        [bucket.address]
    )
}

has_encryption_config(bucket_name) {
    config := s3_encryption_configs[_]
    config.change.after.bucket == bucket_name
}

# =============================================================================
# EFEX-TF-S3-002: S3 buckets must block public access
# Severity: CRITICAL
# Regulation: LFPDPPP, SOC 2 CC6.1 - Data protection
# =============================================================================
deny[msg] {
    bucket := s3_buckets[_]
    bucket_name := bucket.change.after.bucket

    # Check if there's a public access block
    block := s3_public_access_blocks[_]
    block.change.after.bucket == bucket_name

    # Any of these being false is a violation
    not block.change.after.block_public_acls == true

    msg := sprintf(
        "EFEX-TF-S3-002: S3 bucket '%s' must have block_public_acls enabled. Public buckets are prohibited for financial data. Regulation: LFPDPPP.",
        [bucket.address]
    )
}

deny[msg] {
    bucket := s3_buckets[_]
    bucket_name := bucket.change.after.bucket

    block := s3_public_access_blocks[_]
    block.change.after.bucket == bucket_name

    not block.change.after.block_public_policy == true

    msg := sprintf(
        "EFEX-TF-S3-002: S3 bucket '%s' must have block_public_policy enabled.",
        [bucket.address]
    )
}

deny[msg] {
    bucket := s3_buckets[_]
    bucket_name := bucket.change.after.bucket

    block := s3_public_access_blocks[_]
    block.change.after.bucket == bucket_name

    not block.change.after.restrict_public_buckets == true

    msg := sprintf(
        "EFEX-TF-S3-002: S3 bucket '%s' must have restrict_public_buckets enabled.",
        [bucket.address]
    )
}

# =============================================================================
# EFEX-TF-S3-003: S3 bucket ACL must not be public
# Severity: CRITICAL
# Regulation: LFPDPPP, CNBV data protection
# =============================================================================
deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_acl"
    resource.change.actions[_] != "delete"

    acl := resource.change.after.acl
    public_acls := {"public-read", "public-read-write", "authenticated-read"}
    acl in public_acls

    msg := sprintf(
        "EFEX-TF-S3-003: S3 bucket ACL '%s' uses public ACL '%s'. This is prohibited for financial data. Use 'private' ACL.",
        [resource.address, acl]
    )
}

# =============================================================================
# EFEX-TF-S3-004: S3 buckets containing sensitive data must have versioning
# Severity: MEDIUM
# Regulation: SOC 2 CC7.2 - Data recovery
# =============================================================================
warn[msg] {
    bucket := s3_buckets[_]
    bucket_name := bucket.change.after.bucket

    # Check for sensitive bucket names (KYC, PII, transactions)
    contains(lower(bucket_name), "kyc")

    not has_versioning(bucket_name)

    msg := sprintf(
        "EFEX-TF-S3-004: S3 bucket '%s' contains sensitive data and should have versioning enabled for data recovery (SOC 2 CC7.2).",
        [bucket.address]
    )
}

has_versioning(bucket_name) {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_versioning"
    resource.change.after.bucket == bucket_name
    resource.change.after.versioning_configuration[_].status == "Enabled"
}
