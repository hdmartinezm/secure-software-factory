# EFEX Custom Policy: IAM Security
# =================================
# Policy ID: EFEX-TF-IAM-*
# Regulatory Mapping: SOC 2 CC6.3, Principle of Least Privilege
#
# These policies enforce least privilege access for IAM policies and roles.
# Overprivileged IAM is a critical risk for financial services.

package terraform.iam

import future.keywords.in

# Helper: Get all IAM policy resources
iam_policies[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_policy"
    resource.change.actions[_] != "delete"
}

# Helper: Get all IAM role resources
iam_roles[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_iam_role"
    resource.change.actions[_] != "delete"
}

# Helper: Parse policy document
parse_policy(policy_json) = parsed {
    parsed := json.unmarshal(policy_json)
}

# =============================================================================
# EFEX-TF-IAM-001: IAM policies must not use Action: "*"
# Severity: CRITICAL
# Regulation: SOC 2 CC6.3 - Logical Access Controls
# =============================================================================
deny[msg] {
    resource := iam_policies[_]
    policy_json := resource.change.after.policy
    policy := parse_policy(policy_json)

    statement := policy.Statement[_]
    statement.Effect == "Allow"
    action := statement.Action

    # Check if Action is "*" (string)
    action == "*"

    msg := sprintf(
        "EFEX-TF-IAM-001: IAM policy '%s' uses Action:'*' which grants ALL permissions. This violates the principle of least privilege (SOC 2 CC6.3). Specify explicit actions.",
        [resource.address]
    )
}

deny[msg] {
    resource := iam_policies[_]
    policy_json := resource.change.after.policy
    policy := parse_policy(policy_json)

    statement := policy.Statement[_]
    statement.Effect == "Allow"
    actions := statement.Action

    # Check if Action array contains "*"
    is_array(actions)
    actions[_] == "*"

    msg := sprintf(
        "EFEX-TF-IAM-001: IAM policy '%s' contains Action:'*' in action list. Remove wildcard and specify explicit actions.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-IAM-002: IAM policies must not use Resource: "*" with Allow
# Severity: HIGH
# Regulation: SOC 2 CC6.3 - Resource-level permissions
# =============================================================================
deny[msg] {
    resource := iam_policies[_]
    policy_json := resource.change.after.policy
    policy := parse_policy(policy_json)

    statement := policy.Statement[_]
    statement.Effect == "Allow"
    statement.Resource == "*"

    # Check that Action is also broad (not just read actions)
    action := statement.Action
    not is_read_only_action(action)

    msg := sprintf(
        "EFEX-TF-IAM-002: IAM policy '%s' uses Resource:'*' with broad Allow permissions. Specify explicit resource ARNs for financial systems.",
        [resource.address]
    )
}

# Helper: Check if actions are read-only
is_read_only_action(action) {
    is_string(action)
    read_prefixes := ["Get", "List", "Describe", "Head"]
    prefix := read_prefixes[_]
    contains(action, prefix)
}

# =============================================================================
# EFEX-TF-IAM-003: IAM policies must not grant full service access (*:*)
# Severity: CRITICAL
# Regulation: SOC 2 CC6.3
# =============================================================================
deny[msg] {
    resource := iam_policies[_]
    policy_json := resource.change.after.policy
    policy := parse_policy(policy_json)

    statement := policy.Statement[_]
    statement.Effect == "Allow"
    actions := statement.Action

    # Check for service:* patterns
    is_array(actions)
    action := actions[_]
    endswith(action, ":*")

    # Critical services
    critical_services := ["iam:*", "kms:*", "sts:*", "organizations:*"]
    action in critical_services

    msg := sprintf(
        "EFEX-TF-IAM-003: IAM policy '%s' grants full access to critical service '%s'. This is prohibited for financial systems.",
        [resource.address, action]
    )
}

# =============================================================================
# EFEX-TF-IAM-004: IAM roles must not have overly permissive trust policies
# Severity: CRITICAL
# Regulation: SOC 2 CC6.2 - Authentication controls
# =============================================================================
deny[msg] {
    resource := iam_roles[_]
    policy_json := resource.change.after.assume_role_policy
    policy := parse_policy(policy_json)

    statement := policy.Statement[_]
    statement.Effect == "Allow"

    # Check for Principal: "*" or Principal.AWS: "*"
    principal := statement.Principal
    principal == "*"

    msg := sprintf(
        "EFEX-TF-IAM-004: IAM role '%s' has trust policy with Principal:'*' allowing ANY entity to assume this role. This is a critical security risk.",
        [resource.address]
    )
}

deny[msg] {
    resource := iam_roles[_]
    policy_json := resource.change.after.assume_role_policy
    policy := parse_policy(policy_json)

    statement := policy.Statement[_]
    statement.Effect == "Allow"

    principal := statement.Principal
    principal.AWS == "*"

    msg := sprintf(
        "EFEX-TF-IAM-004: IAM role '%s' allows any AWS account to assume this role (Principal.AWS:'*'). Restrict to specific accounts.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-IAM-005: Warn on broad service permissions
# Severity: MEDIUM
# =============================================================================
warn[msg] {
    resource := iam_policies[_]
    policy_json := resource.change.after.policy
    policy := parse_policy(policy_json)

    statement := policy.Statement[_]
    statement.Effect == "Allow"
    actions := statement.Action

    is_array(actions)
    action := actions[_]

    # Broad patterns like "s3:*", "ec2:*"
    endswith(action, ":*")
    not action in ["iam:*", "kms:*", "sts:*", "organizations:*"]  # Critical ones are deny, not warn

    msg := sprintf(
        "EFEX-TF-IAM-005: IAM policy '%s' uses broad service permission '%s'. Consider restricting to specific actions needed.",
        [resource.address, action]
    )
}
