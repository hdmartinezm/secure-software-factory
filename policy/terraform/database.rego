# EFEX Custom Policy: Database Security
# ======================================
# Policy ID: EFEX-TF-DB-*
# Regulatory Mapping: CNBV encryption requirements, SOC 2 CC6.1
#
# These policies enforce security controls for RDS and other database
# resources handling financial transaction data.

package terraform.database

# Helper: Get RDS instances
rds_instances[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_db_instance"
    resource.change.actions[_] != "delete"
}

# Helper: Get RDS clusters
rds_clusters[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_rds_cluster"
    resource.change.actions[_] != "delete"
}

# =============================================================================
# EFEX-TF-DB-001: RDS instances must have encryption at rest
# Severity: CRITICAL
# Regulation: CNBV Art. 316 Bis 17, SOC 2 CC6.1
# =============================================================================
deny[msg] {
    resource := rds_instances[_]

    # Check if storage_encrypted is false or not set
    not resource.change.after.storage_encrypted == true

    msg := sprintf(
        "EFEX-TF-DB-001: RDS instance '%s' must have storage encryption enabled (storage_encrypted = true). Required for CNBV Art. 316 Bis 17 - encryption of financial data at rest.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-DB-002: RDS instances must not be publicly accessible
# Severity: CRITICAL
# Regulation: CNBV network segmentation, SOC 2 CC6.6
# =============================================================================
deny[msg] {
    resource := rds_instances[_]

    resource.change.after.publicly_accessible == true

    msg := sprintf(
        "EFEX-TF-DB-002: RDS instance '%s' must not be publicly accessible. Financial databases must be in private subnets only.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-DB-003: RDS instances must have deletion protection enabled
# Severity: HIGH
# Regulation: SOC 2 CC7.2 - Data protection
# =============================================================================
deny[msg] {
    resource := rds_instances[_]

    # Check for production-looking identifiers
    identifier := resource.change.after.identifier
    contains(identifier, "prod")

    not resource.change.after.deletion_protection == true

    msg := sprintf(
        "EFEX-TF-DB-003: Production RDS instance '%s' must have deletion_protection enabled to prevent accidental data loss.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-DB-004: RDS instances must have backup retention
# Severity: HIGH
# Regulation: CNBV data retention, SOC 2 CC7.2
# =============================================================================
deny[msg] {
    resource := rds_instances[_]

    # backup_retention_period of 0 means backups disabled
    resource.change.after.backup_retention_period == 0

    msg := sprintf(
        "EFEX-TF-DB-004: RDS instance '%s' has no backup retention configured. Financial data requires minimum 7 days backup retention per CNBV requirements.",
        [resource.address]
    )
}

warn[msg] {
    resource := rds_instances[_]

    retention := resource.change.after.backup_retention_period
    retention > 0
    retention < 7

    msg := sprintf(
        "EFEX-TF-DB-004: RDS instance '%s' has backup retention of %d days. Recommend minimum 7 days for financial data.",
        [resource.address, retention]
    )
}

# =============================================================================
# EFEX-TF-DB-005: RDS instances should have performance insights enabled
# Severity: LOW
# Regulation: SOC 2 CC7.1 - Monitoring
# =============================================================================
warn[msg] {
    resource := rds_instances[_]

    not resource.change.after.performance_insights_enabled == true

    msg := sprintf(
        "EFEX-TF-DB-005: RDS instance '%s' should have Performance Insights enabled for monitoring and audit purposes.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-DB-006: RDS clusters must have encryption
# Severity: CRITICAL
# Regulation: CNBV Art. 316 Bis 17
# =============================================================================
deny[msg] {
    resource := rds_clusters[_]

    not resource.change.after.storage_encrypted == true

    msg := sprintf(
        "EFEX-TF-DB-006: RDS cluster '%s' must have storage encryption enabled.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-DB-007: RDS should not skip final snapshot
# Severity: MEDIUM
# Regulation: Data recovery requirements
# =============================================================================
warn[msg] {
    resource := rds_instances[_]

    resource.change.after.skip_final_snapshot == true

    msg := sprintf(
        "EFEX-TF-DB-007: RDS instance '%s' is configured to skip final snapshot. Consider enabling for disaster recovery.",
        [resource.address]
    )
}
