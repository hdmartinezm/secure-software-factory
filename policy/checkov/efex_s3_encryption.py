"""
EFEX Custom Check: S3 Bucket Encryption
=======================================
Check ID: EFEX_AWS_001
Severity: HIGH

Ensures all S3 buckets have server-side encryption enabled.
This is required for CNBV Art. 316 Bis 17 compliance.
"""

from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class EFEXS3Encryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure S3 bucket has encryption enabled (EFEX-CNBV)"
        id = "EFEX_AWS_001"
        supported_resources = ["aws_s3_bucket"]
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
            guideline="S3 buckets containing financial data must have server-side encryption. "
                      "Add aws_s3_bucket_server_side_encryption_configuration resource. "
                      "Regulation: CNBV Art. 316 Bis 17, SOC 2 CC6.1"
        )

    def scan_resource_conf(self, conf):
        """
        Check for encryption configuration.
        Note: In newer AWS provider versions, encryption is configured via
        separate aws_s3_bucket_server_side_encryption_configuration resource.
        This check validates the bucket itself has encryption references.
        """
        # Check for inline server_side_encryption_configuration (older provider)
        if "server_side_encryption_configuration" in conf:
            encryption_config = conf["server_side_encryption_configuration"]
            if encryption_config and len(encryption_config) > 0:
                return CheckResult.PASSED

        # For newer providers, this check will be complemented by
        # checking the separate encryption configuration resource
        # Return UNKNOWN to indicate manual review needed
        return CheckResult.FAILED


check = EFEXS3Encryption()
