# EFEX S3 Public Access Policy
# =============================
# Policy ID: EFEX_AWS_003
# Severity: CRITICAL
#
# Ensures all S3 buckets have public access blocked.
# Required for CNBV Art. 316 Bis 17 compliance - financial data
# must never be publicly accessible.

package terraform.s3

import rego.v1

# Deny S3 buckets without public access block
deny contains msg if {
    bucket := input.resource_changes[_]
    bucket.type == "aws_s3_bucket"
    bucket.change.actions[_] != "delete"

    bucket_address := bucket.address

    not has_public_access_block(bucket_address)

    msg := sprintf(
        "EFEX_AWS_003: S3 bucket '%s' does not have public access blocked. " +
        "Add aws_s3_bucket_public_access_block resource with all flags set to true. " +
        "Regulation: CNBV Art. 316 Bis 17 - Financial data must not be publicly accessible",
        [bucket_address]
    )
}

# Check if bucket has public access block resource
has_public_access_block(bucket_address) if {
    parts := split(bucket_address, ".")
    bucket_name := parts[count(parts) - 1]

    pab := input.resource_changes[_]
    pab.type == "aws_s3_bucket_public_access_block"
    pab.change.actions[_] != "delete"

    contains(pab.address, bucket_name)
}

# Deny public access blocks that don't block everything
deny contains msg if {
    pab := input.resource_changes[_]
    pab.type == "aws_s3_bucket_public_access_block"
    pab.change.actions[_] != "delete"

    after := pab.change.after

    # All four flags must be true
    not all_blocked(after)

    msg := sprintf(
        "EFEX_AWS_004: Public access block '%s' does not block all public access. " +
        "Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.",
        [pab.address]
    )
}

# Helper to check all public access is blocked
all_blocked(config) if {
    config.block_public_acls == true
    config.block_public_policy == true
    config.ignore_public_acls == true
    config.restrict_public_buckets == true
}
