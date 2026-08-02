# EFEX S3 Encryption Policy
# =========================
# Policy ID: EFEX_AWS_001
# Severity: HIGH
#
# Ensures all S3 buckets have server-side encryption enabled.
# Required for CNBV Art. 316 Bis 17 compliance.
#
# This OPA policy properly validates the relationship between:
#   - aws_s3_bucket resources
#   - aws_s3_bucket_server_side_encryption_configuration resources
#
# Unlike simple resource checks, this can verify cross-resource relationships
# in Terraform plans.

package terraform.s3

import rego.v1

# Deny S3 buckets without encryption configuration
deny contains msg if {
    # Find all S3 buckets being created or updated
    bucket := input.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    bucket.change.actions[_] != "delete"

    # Get the bucket address (e.g., "aws_s3_bucket.kyc_documents")
    bucket_address := bucket.address

    # Check if there's a corresponding encryption configuration
    not has_encryption_config(bucket_address)

    msg := sprintf(
        "EFEX_AWS_001: S3 bucket '%s' does not have server-side encryption configured. " +
        "Add aws_s3_bucket_server_side_encryption_configuration resource. " +
        "Regulation: CNBV Art. 316 Bis 17, SOC 2 CC6.1",
        [bucket_address]
    )
}

# Check if bucket has inline encryption (older AWS provider style)
has_inline_encryption(bucket) if {
    bucket.change.after.server_side_encryption_configuration
}

# Check if bucket has separate encryption config resource
has_encryption_config(bucket_address) if {
    # Extract the resource name from the address
    # e.g., "aws_s3_bucket.kyc_documents" -> "kyc_documents"
    parts := split(bucket_address, ".")
    bucket_name := parts[count(parts) - 1]

    # Look for encryption configuration resources that reference this bucket
    encryption := input.resource_changes[_]
    encryption.type == "aws_s3_bucket_server_side_encryption_configuration"
    encryption.change.actions[_] != "delete"

    # Check if the encryption config references this bucket
    # The bucket attribute contains the bucket ID or reference
    references_bucket(encryption, bucket_name)
}

# Check if encryption config references the bucket by name in its address
references_bucket(encryption, bucket_name) if {
    contains(encryption.address, bucket_name)
}

# Check if encryption config references the bucket in its configuration
references_bucket(encryption, bucket_name) if {
    bucket_ref := encryption.change.after.bucket
    contains(bucket_ref, bucket_name)
}

# Also check via the before_sensitive or after_unknown for references
references_bucket(encryption, bucket_name) if {
    # For terraform plan, references are sometimes in the configuration
    encryption.change.before != null
    contains(encryption.address, bucket_name)
}

# Deny S3 buckets with weak encryption algorithm
deny contains msg if {
    encryption := input.resource_changes[_]
    encryption.type == "aws_s3_bucket_server_side_encryption_configuration"
    encryption.change.actions[_] != "delete"

    # Check if using AES256 instead of KMS (warning for CNBV compliance)
    rule := encryption.change.after.rule[_]
    default_encryption := rule.apply_server_side_encryption_by_default
    default_encryption.sse_algorithm == "AES256"

    msg := sprintf(
        "EFEX_AWS_002: S3 encryption '%s' uses AES256. Consider using aws:kms with customer-managed key " +
        "for CNBV Art. 316 Bis 17 compliance (key rotation, audit trail).",
        [encryption.address]
    )
}

# Informational: Report buckets with KMS encryption (compliant)
compliant contains msg if {
    encryption := input.resource_changes[_]
    encryption.type == "aws_s3_bucket_server_side_encryption_configuration"
    encryption.change.actions[_] != "delete"

    rule := encryption.change.after.rule[_]
    default_encryption := rule.apply_server_side_encryption_by_default
    default_encryption.sse_algorithm == "aws:kms"

    msg := sprintf(
        "EFEX_AWS_001_PASS: S3 encryption '%s' correctly configured with KMS encryption",
        [encryption.address]
    )
}
