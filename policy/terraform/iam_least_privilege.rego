# EFEX IAM Least Privilege Policy
# ================================
# Policy ID: EFEX_AWS_010
# Severity: HIGH
#
# Ensures IAM policies follow least privilege principle.
# Required for SOC 2 CC6.3, CNBV Art. 316 Bis 12 compliance.

package terraform.iam

import rego.v1

# Deny IAM policies with wildcard actions
deny contains msg if {
    policy := input.resource_changes[_]
    policy.type == "aws_iam_policy"
    policy.change.actions[_] != "delete"

    # Parse the policy document
    policy_doc := json.unmarshal(policy.change.after.policy)
    statement := policy_doc.Statement[_]

    # Check for wildcard actions
    has_wildcard_action(statement)

    msg := sprintf(
        "EFEX_AWS_010: IAM policy '%s' uses wildcard actions (*). " +
        "Specify explicit actions following least privilege principle. " +
        "Regulation: SOC 2 CC6.3, CNBV Art. 316 Bis 12",
        [policy.address]
    )
}

# Check for wildcard in action
has_wildcard_action(statement) if {
    action := statement.Action[_]
    action == "*"
}

has_wildcard_action(statement) if {
    statement.Action == "*"
}

has_wildcard_action(statement) if {
    action := statement.Action[_]
    endswith(action, ":*")
}

has_wildcard_action(statement) if {
    endswith(statement.Action, ":*")
}

# Deny IAM policies with wildcard resources for sensitive actions
deny contains msg if {
    policy := input.resource_changes[_]
    policy.type == "aws_iam_policy"
    policy.change.actions[_] != "delete"

    policy_doc := json.unmarshal(policy.change.after.policy)
    statement := policy_doc.Statement[_]

    # Check for wildcard resources with sensitive actions
    has_wildcard_resource(statement)
    has_sensitive_action(statement)

    msg := sprintf(
        "EFEX_AWS_011: IAM policy '%s' grants sensitive permissions to all resources (*). " +
        "Scope resources to specific ARNs. " +
        "Regulation: SOC 2 CC6.3",
        [policy.address]
    )
}

# Check for wildcard in resource
has_wildcard_resource(statement) if {
    resource := statement.Resource[_]
    resource == "*"
}

has_wildcard_resource(statement) if {
    statement.Resource == "*"
}

# Sensitive actions that should never have wildcard resources
sensitive_actions := {
    "s3:*", "s3:GetObject", "s3:PutObject", "s3:DeleteObject",
    "kms:*", "kms:Decrypt", "kms:Encrypt",
    "secretsmanager:GetSecretValue",
    "iam:*", "iam:CreateUser", "iam:AttachRolePolicy",
    "ec2:*", "rds:*"
}

has_sensitive_action(statement) if {
    action := statement.Action[_]
    action in sensitive_actions
}

has_sensitive_action(statement) if {
    statement.Action in sensitive_actions
}
