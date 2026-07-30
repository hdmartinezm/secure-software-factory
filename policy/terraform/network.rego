# EFEX Custom Policy: Network Security
# =====================================
# Policy ID: EFEX-TF-NET-*
# Regulatory Mapping: SOC 2 CC6.6, CNBV network segmentation
#
# These policies enforce network security controls for security groups,
# VPCs, and other network resources.

package terraform.network

import future.keywords.in

# Helper: Get security groups
security_groups[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group"
    resource.change.actions[_] != "delete"
}

# Helper: Get security group rules
security_group_rules[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    resource.change.actions[_] != "delete"
}

# Sensitive ports that should never be open to the internet
sensitive_ports := {
    22,    # SSH
    3389,  # RDP
    3306,  # MySQL
    5432,  # PostgreSQL
    27017, # MongoDB
    6379,  # Redis
    11211, # Memcached
    9200,  # Elasticsearch
    5601,  # Kibana
}

# Public CIDR blocks
public_cidrs := {
    "0.0.0.0/0",
    "::/0",
}

# =============================================================================
# EFEX-TF-NET-001: Security groups must not allow unrestricted inbound access
# Severity: CRITICAL
# Regulation: SOC 2 CC6.6, CNBV network segmentation
# =============================================================================
deny[msg] {
    resource := security_groups[_]
    ingress := resource.change.after.ingress[_]

    # Check for 0.0.0.0/0 in CIDR blocks
    cidr := ingress.cidr_blocks[_]
    cidr in public_cidrs

    # Port range that includes sensitive ports
    from_port := ingress.from_port
    to_port := ingress.to_port

    # If range includes any sensitive port
    sensitive_port := sensitive_ports[_]
    from_port <= sensitive_port
    to_port >= sensitive_port

    msg := sprintf(
        "EFEX-TF-NET-001: Security group '%s' allows public access (0.0.0.0/0) to sensitive port %d. This is prohibited per CNBV network segmentation requirements.",
        [resource.address, sensitive_port]
    )
}

# =============================================================================
# EFEX-TF-NET-002: SSH (port 22) must not be open to the world
# Severity: CRITICAL
# Regulation: SOC 2 CC6.6
# =============================================================================
deny[msg] {
    resource := security_groups[_]
    ingress := resource.change.after.ingress[_]

    cidr := ingress.cidr_blocks[_]
    cidr in public_cidrs

    # SSH port range check
    ingress.from_port <= 22
    ingress.to_port >= 22

    msg := sprintf(
        "EFEX-TF-NET-002: Security group '%s' allows SSH (port 22) from the internet. Use VPN or bastion host instead.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-NET-003: Database ports must not be public
# Severity: CRITICAL
# Regulation: CNBV data protection, SOC 2 CC6.6
# =============================================================================
deny[msg] {
    resource := security_groups[_]
    ingress := resource.change.after.ingress[_]

    cidr := ingress.cidr_blocks[_]
    cidr in public_cidrs

    # MySQL port
    ingress.from_port <= 3306
    ingress.to_port >= 3306

    msg := sprintf(
        "EFEX-TF-NET-003: Security group '%s' exposes MySQL (port 3306) to the internet. Database ports must be internal only.",
        [resource.address]
    )
}

deny[msg] {
    resource := security_groups[_]
    ingress := resource.change.after.ingress[_]

    cidr := ingress.cidr_blocks[_]
    cidr in public_cidrs

    # PostgreSQL port
    ingress.from_port <= 5432
    ingress.to_port >= 5432

    msg := sprintf(
        "EFEX-TF-NET-003: Security group '%s' exposes PostgreSQL (port 5432) to the internet. Database ports must be internal only.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-NET-004: Security groups should not allow all ports
# Severity: HIGH
# Regulation: SOC 2 CC6.6 - Network restrictions
# =============================================================================
deny[msg] {
    resource := security_groups[_]
    ingress := resource.change.after.ingress[_]

    cidr := ingress.cidr_blocks[_]
    cidr in public_cidrs

    # All ports (0-65535)
    ingress.from_port == 0
    ingress.to_port == 65535

    msg := sprintf(
        "EFEX-TF-NET-004: Security group '%s' allows ALL ports (0-65535) from the internet. Restrict to specific required ports.",
        [resource.address]
    )
}

# =============================================================================
# EFEX-TF-NET-005: VPC must have flow logs enabled
# Severity: MEDIUM
# Regulation: SOC 2 CC7.1 - Monitoring and logging
# =============================================================================
vpc_resources[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_vpc"
    resource.change.actions[_] != "delete"
}

flow_log_resources[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_flow_log"
    resource.change.actions[_] != "delete"
}

warn[msg] {
    vpc := vpc_resources[_]

    # Check if there's a flow log for this VPC
    not has_flow_log(vpc.change.after.id)

    msg := sprintf(
        "EFEX-TF-NET-005: VPC '%s' should have flow logs enabled for network traffic monitoring (SOC 2 CC7.1).",
        [vpc.address]
    )
}

has_flow_log(vpc_id) {
    flow_log := flow_log_resources[_]
    flow_log.change.after.vpc_id == vpc_id
}

# =============================================================================
# EFEX-TF-NET-006: Security group rule check (standalone rules)
# Severity: CRITICAL
# =============================================================================
deny[msg] {
    resource := security_group_rules[_]
    resource.change.after.type == "ingress"

    cidr := resource.change.after.cidr_blocks[_]
    cidr in public_cidrs

    port := resource.change.after.from_port
    port in sensitive_ports

    msg := sprintf(
        "EFEX-TF-NET-006: Security group rule '%s' allows public access to sensitive port %d.",
        [resource.address, port]
    )
}
