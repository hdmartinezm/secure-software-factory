# =============================================================================
# EFEX Secure Software Factory - VULNERABLE Infrastructure (DEMO)
# =============================================================================
# This Terraform contains INTENTIONAL security misconfigurations for demo.
# DO NOT USE IN PRODUCTION.
#
# Vulnerabilities:
# - EFEX-VULN-013: S3 without encryption
# - EFEX-VULN-014: S3 public access enabled
# - EFEX-VULN-015: IAM Action: "*"
# - EFEX-VULN-016: IAM Resource: "*"
# - EFEX-VULN-017: Security Group open to 0.0.0.0/0
# - EFEX-VULN-018: RDS without encryption
# - EFEX-VULN-019: RDS publicly accessible
# =============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# =============================================================================
# EFEX-VULN-013 & 014: S3 Bucket - No encryption, public access
# =============================================================================
resource "aws_s3_bucket" "kyc_documents" {
  bucket = "efex-kyc-documents-demo"

  tags = {
    Name        = "EFEX KYC Documents"
    Environment = "demo"
    Vulnerable  = "true"
  }
}

# VULNERABLE: No encryption configured
# Missing: aws_s3_bucket_server_side_encryption_configuration

# VULNERABLE: Public access not blocked
resource "aws_s3_bucket_public_access_block" "kyc_documents" {
  bucket = aws_s3_bucket.kyc_documents.id

  # All set to false = PUBLIC ACCESS ALLOWED (VULNERABLE)
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# =============================================================================
# EFEX-VULN-015 & 016: IAM Policy with wildcards
# =============================================================================
resource "aws_iam_policy" "transfer_service" {
  name        = "efex-transfer-service-policy-demo"
  description = "VULNERABLE: Overly permissive policy with wildcards"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # VULNERABLE: Action "*" allows ALL actions
        Effect   = "Allow"
        Action   = "*"
        # VULNERABLE: Resource "*" allows access to ALL resources
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "transfer_service" {
  name = "efex-transfer-service-role-demo"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "transfer_service" {
  role       = aws_iam_role.transfer_service.name
  policy_arn = aws_iam_policy.transfer_service.arn
}

# =============================================================================
# EFEX-VULN-017: Security Group open to the world
# =============================================================================
resource "aws_security_group" "api_service" {
  name        = "efex-api-service-demo"
  description = "VULNERABLE: Open to 0.0.0.0/0"

  # VULNERABLE: SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "VULNERABLE: SSH from anywhere"
  }

  # VULNERABLE: API port open to the world
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "VULNERABLE: API from anywhere"
  }

  # VULNERABLE: Database port open to the world
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "VULNERABLE: PostgreSQL from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name       = "EFEX API Service"
    Vulnerable = "true"
  }
}

# =============================================================================
# EFEX-VULN-018 & 019: RDS without encryption, publicly accessible
# =============================================================================
resource "aws_db_instance" "transfers" {
  identifier           = "efex-transfers-demo"
  allocated_storage    = 20
  engine               = "postgres"
  engine_version       = "13"
  instance_class       = "db.t3.micro"
  db_name              = "transfers"
  username             = "admin"
  password             = "demo_password_not_real"  # VULNERABLE: Hardcoded password
  skip_final_snapshot  = true

  # VULNERABLE: No encryption at rest
  storage_encrypted = false

  # VULNERABLE: Publicly accessible
  publicly_accessible = true

  # VULNERABLE: No deletion protection
  deletion_protection = false

  tags = {
    Name       = "EFEX Transfers DB"
    Vulnerable = "true"
  }
}

# =============================================================================
# Outputs
# =============================================================================
output "s3_bucket_name" {
  value       = aws_s3_bucket.kyc_documents.id
  description = "KYC documents bucket (VULNERABLE: public, unencrypted)"
}

output "rds_endpoint" {
  value       = aws_db_instance.transfers.endpoint
  description = "RDS endpoint (VULNERABLE: public, unencrypted)"
}
