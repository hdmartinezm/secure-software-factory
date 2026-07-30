# EFEX Infrastructure - VULNERABLE Terraform Configuration
# =========================================================
# Esta configuracion contiene misconfigs INTENCIONALES para demostrar
# el pipeline DevSecOps con Checkov/Conftest. NO usar en produccion.
#
# Vulnerabilidades incluidas:
# - EFEX-VULN-013: S3 bucket sin cifrado en reposo
# - EFEX-VULN-014: S3 bucket publico
# - EFEX-VULN-015: IAM policy con Action: "*"
# - EFEX-VULN-016: IAM policy con Resource: "*"
# - EFEX-VULN-017: Security Group abierto a 0.0.0.0/0
# - EFEX-VULN-018: RDS sin cifrado
# - EFEX-VULN-019: RDS publicamente accesible
# - EFEX-VULN-020: CloudWatch logs sin cifrado
# - EFEX-VULN-021: No VPC flow logs

locals {
  environment = "production"
  project     = "efex-transfers"

  # EFEX-VULN: Hardcoded sensitive values in Terraform
  db_password = "efex_prod_password_2024!"
}

# =============================================================================
# S3 BUCKETS - KYC Documents Storage
# =============================================================================

# EFEX-VULN-013: S3 bucket without encryption at rest
# Detectado por: Checkov (CKV_AWS_19), Conftest custom policy
# Regulacion: CNBV Art. 316 Bis 17, SOC 2 CC6.1
# Riesgo: Documentos KYC (INE, comprobantes) expuestos sin cifrado
resource "aws_s3_bucket" "kyc_documents" {
  bucket = "efex-kyc-documents-prod"

  tags = {
    Name        = "EFEX KYC Documents"
    Environment = local.environment
    Compliance  = "CNBV-IFPE"
  }
}

# EFEX-VULN-014: S3 bucket with public access enabled
# Detectado por: Checkov (CKV_AWS_20, CKV_AWS_21)
# Regulacion: CNBV datos personales, LFPDPPP
# Riesgo: Datos KYC/AML accesibles publicamente = multas + fraude
resource "aws_s3_bucket_public_access_block" "kyc_public_access" {
  bucket = aws_s3_bucket.kyc_documents.id

  # VULNERABLE: All public access controls DISABLED
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# EFEX-VULN: ACL set to public-read
resource "aws_s3_bucket_acl" "kyc_acl" {
  bucket = aws_s3_bucket.kyc_documents.id
  acl    = "public-read"
}

# Second S3 bucket for transaction logs - also vulnerable
resource "aws_s3_bucket" "transaction_logs" {
  bucket = "efex-transaction-logs-prod"

  # EFEX-VULN: No versioning = can't recover from accidental deletes
  # Detectado por: Checkov (CKV_AWS_21)
}

# =============================================================================
# IAM POLICIES - Service Permissions
# =============================================================================

# EFEX-VULN-015 & EFEX-VULN-016: Overprivileged IAM policy
# Detectado por: Checkov (CKV_AWS_1, CKV_AWS_49), Conftest custom policy
# Regulacion: SOC 2 CC6.3, principio de minimo privilegio
# Riesgo: Compromiso de credenciales = acceso total a AWS account
resource "aws_iam_policy" "transfer_service_policy" {
  name        = "efex-transfer-service-policy"
  description = "Policy for EFEX transfer service"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "FullAccess"
        Effect = "Allow"
        # VULNERABLE: Action "*" allows ALL AWS actions
        Action = "*"
        # VULNERABLE: Resource "*" applies to ALL resources
        Resource = "*"
      }
    ]
  })
}

# Another overprivileged policy for "admin" operations
resource "aws_iam_policy" "admin_policy" {
  name        = "efex-admin-policy"
  description = "Admin policy for EFEX operations"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:*",
          "rds:*",
          "iam:*",
          "kms:*"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM role without proper trust policy constraints
resource "aws_iam_role" "transfer_service_role" {
  name = "efex-transfer-service-role"

  # EFEX-VULN: Overly permissive trust policy
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          # VULNERABLE: Allows any AWS account to assume this role
          AWS = "*"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "transfer_service_attachment" {
  role       = aws_iam_role.transfer_service_role.name
  policy_arn = aws_iam_policy.transfer_service_policy.arn
}

# =============================================================================
# SECURITY GROUPS - Network Access Control
# =============================================================================

# EFEX-VULN-017: Security Group open to the world
# Detectado por: Checkov (CKV_AWS_23, CKV_AWS_24, CKV_AWS_25)
# Regulacion: SOC 2 CC6.6, CNBV segmentacion de red
# Riesgo: Cualquier IP puede acceder a servicios internos
resource "aws_security_group" "api_service" {
  name        = "efex-api-service-sg"
  description = "Security group for EFEX API service"
  vpc_id      = aws_vpc.main.id

  # VULNERABLE: SSH open to entire internet
  ingress {
    description = "SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABLE: All ports open to 0.0.0.0/0
  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # VULNERABLE: Allowing all outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "EFEX API Security Group"
  }
}

# Database security group - also insecure
resource "aws_security_group" "database" {
  name        = "efex-database-sg"
  description = "Security group for EFEX database"
  vpc_id      = aws_vpc.main.id

  # VULNERABLE: Database port open to internet
  ingress {
    description = "MySQL access"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "EFEX Database Security Group"
  }
}

# =============================================================================
# VPC - Network Infrastructure
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  # EFEX-VULN-021: DNS hostnames enabled but no flow logs
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "EFEX Production VPC"
  }
}

# EFEX-VULN: No VPC Flow Logs configured
# Detectado por: Checkov (CKV_AWS_12)
# Regulacion: SOC 2 CC7.1, CNBV trazabilidad
# Missing: aws_flow_log resource

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"

  # EFEX-VULN: Public IPs assigned by default
  map_public_ip_on_launch = true

  tags = {
    Name = "EFEX Public Subnet"
  }
}

# =============================================================================
# RDS - Database
# =============================================================================

# EFEX-VULN-018 & EFEX-VULN-019: RDS without encryption and publicly accessible
# Detectado por: Checkov (CKV_AWS_16, CKV_AWS_17)
# Regulacion: CNBV cifrado en reposo, PCI-DSS
# Riesgo: Datos financieros sin cifrar + accesibles desde internet
resource "aws_db_instance" "transfers" {
  identifier     = "efex-transfers-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.medium"

  db_name  = "transfers"
  username = "efex_admin"
  # EFEX-VULN: Hardcoded password in Terraform
  password = local.db_password

  # VULNERABLE: No encryption at rest
  storage_encrypted = false

  # VULNERABLE: Publicly accessible
  publicly_accessible = true

  # VULNERABLE: No deletion protection
  deletion_protection = false

  # VULNERABLE: Skip final snapshot
  skip_final_snapshot = true

  # VULNERABLE: No backup retention
  backup_retention_period = 0

  # VULNERABLE: Performance insights disabled (no monitoring)
  performance_insights_enabled = false

  vpc_security_group_ids = [aws_security_group.database.id]

  tags = {
    Name        = "EFEX Transfers Database"
    Environment = local.environment
  }
}

# =============================================================================
# CLOUDWATCH - Logging
# =============================================================================

# EFEX-VULN-020: CloudWatch Log Group without encryption
# Detectado por: Checkov (CKV_AWS_97)
resource "aws_cloudwatch_log_group" "api_logs" {
  name = "/efex/api/logs"

  # VULNERABLE: No KMS encryption
  # Missing: kms_key_id

  # VULNERABLE: Short retention
  retention_in_days = 7

  tags = {
    Application = "EFEX API"
  }
}

# =============================================================================
# ECR - Container Registry
# =============================================================================

# EFEX-VULN: ECR without image scanning
resource "aws_ecr_repository" "api" {
  name = "efex-api"

  # VULNERABLE: No image scanning on push
  image_scanning_configuration {
    scan_on_push = false
  }

  # VULNERABLE: Mutable image tags (can be overwritten)
  image_tag_mutability = "MUTABLE"

  # VULNERABLE: No encryption configuration (uses default, but should be explicit)
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "s3_bucket_name" {
  value       = aws_s3_bucket.kyc_documents.id
  description = "Name of the KYC documents S3 bucket"
}

output "database_endpoint" {
  value       = aws_db_instance.transfers.endpoint
  description = "RDS database endpoint"
  sensitive   = true
}

output "api_security_group_id" {
  value       = aws_security_group.api_service.id
  description = "Security group ID for API service"
}
