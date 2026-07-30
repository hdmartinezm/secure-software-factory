"""
EFEX Custom Check: RDS Security
===============================
Check ID: EFEX_AWS_003
Severity: CRITICAL

Ensures RDS instances are not publicly accessible and have encryption.
Financial databases must be isolated and encrypted.
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class EFEXRDSNotPublic(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instance is not publicly accessible (EFEX-CNBV)"
        id = "EFEX_AWS_003"
        supported_resources = ["aws_db_instance"]
        categories = [CheckCategories.NETWORKING]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
            guideline="RDS instances containing financial data must not be publicly accessible. "
                      "Set publicly_accessible = false. "
                      "Regulation: CNBV network segmentation, SOC 2 CC6.6"
        )

    def scan_resource_conf(self, conf):
        """
        Check if RDS is publicly accessible.
        """
        publicly_accessible = conf.get("publicly_accessible", [False])

        # Handle list format from Terraform
        if isinstance(publicly_accessible, list):
            publicly_accessible = publicly_accessible[0] if publicly_accessible else False

        if publicly_accessible is True:
            return CheckResult.FAILED

        return CheckResult.PASSED


class EFEXRDSEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instance has encryption enabled (EFEX-CNBV)"
        id = "EFEX_AWS_004"
        supported_resources = ["aws_db_instance"]
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
            guideline="RDS instances must have storage encryption enabled. "
                      "Set storage_encrypted = true. "
                      "Regulation: CNBV Art. 316 Bis 17, SOC 2 CC6.1"
        )

    def scan_resource_conf(self, conf):
        """
        Check if RDS has storage encryption enabled.
        """
        storage_encrypted = conf.get("storage_encrypted", [False])

        if isinstance(storage_encrypted, list):
            storage_encrypted = storage_encrypted[0] if storage_encrypted else False

        if storage_encrypted is not True:
            return CheckResult.FAILED

        return CheckResult.PASSED


class EFEXRDSBackup(BaseResourceCheck):
    def __init__(self):
        name = "Ensure RDS instance has backup retention configured (EFEX-CNBV)"
        id = "EFEX_AWS_005"
        supported_resources = ["aws_db_instance"]
        categories = [CheckCategories.BACKUP_AND_RECOVERY]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
            guideline="RDS instances must have backup retention configured (minimum 7 days recommended). "
                      "Set backup_retention_period >= 7. "
                      "Regulation: CNBV data retention, SOC 2 CC7.2"
        )

    def scan_resource_conf(self, conf):
        """
        Check if RDS has backup retention configured.
        """
        backup_retention = conf.get("backup_retention_period", [0])

        if isinstance(backup_retention, list):
            backup_retention = backup_retention[0] if backup_retention else 0

        # backup_retention_period of 0 means backups disabled
        if backup_retention == 0:
            return CheckResult.FAILED

        return CheckResult.PASSED


check_public = EFEXRDSNotPublic()
check_encryption = EFEXRDSEncryption()
check_backup = EFEXRDSBackup()
