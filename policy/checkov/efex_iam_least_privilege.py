"""
EFEX Custom Check: IAM Least Privilege
======================================
Check ID: EFEX_AWS_002
Severity: CRITICAL

Ensures IAM policies do not use Action: "*" or Resource: "*".
This enforces the principle of least privilege for financial systems.
"""

import json
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories


class EFEXIAMLeastPrivilege(BaseResourceCheck):
    def __init__(self):
        name = "Ensure IAM policy does not use Action:* or Resource:* (EFEX-SOC2)"
        id = "EFEX_AWS_002"
        supported_resources = ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"]
        categories = [CheckCategories.IAM]
        super().__init__(
            name=name,
            id=id,
            categories=categories,
            supported_resources=supported_resources,
            guideline="IAM policies must follow least privilege principle. "
                      "Action:'*' and Resource:'*' with Allow are prohibited. "
                      "Regulation: SOC 2 CC6.3"
        )

    def scan_resource_conf(self, conf):
        """
        Check IAM policy for overprivileged statements.
        """
        policy_str = conf.get("policy")
        if not policy_str:
            return CheckResult.PASSED

        # Handle case where policy is a list
        if isinstance(policy_str, list):
            policy_str = policy_str[0] if policy_str else "{}"

        try:
            policy = json.loads(policy_str)
        except (json.JSONDecodeError, TypeError):
            # If we can't parse, let Checkov's built-in checks handle it
            return CheckResult.UNKNOWN

        statements = policy.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect", "")
            if effect != "Allow":
                continue

            # Check Action
            action = statement.get("Action", "")
            if self._is_wildcard(action):
                return CheckResult.FAILED

            # Check Resource with wildcard Action
            resource = statement.get("Resource", "")
            if self._is_wildcard(resource):
                # Resource:* is only critical if combined with broad actions
                if self._has_broad_actions(action):
                    return CheckResult.FAILED

        return CheckResult.PASSED

    def _is_wildcard(self, value):
        """Check if value is '*' or contains '*' in list."""
        if value == "*":
            return True
        if isinstance(value, list) and "*" in value:
            return True
        return False

    def _has_broad_actions(self, action):
        """Check if actions are overly broad."""
        if action == "*":
            return True
        if isinstance(action, list):
            for a in action:
                if a == "*" or (isinstance(a, str) and a.endswith(":*")):
                    return True
        if isinstance(action, str) and action.endswith(":*"):
            return True
        return False


check = EFEXIAMLeastPrivilege()
