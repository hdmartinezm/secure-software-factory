# EFEX Infrastructure - SECURE Terraform Configuration
# =====================================================
# This configuration follows security best practices:
# - S3 encryption enabled
# - S3 public access blocked
# - IAM least privilege
# - Security groups restricted
# - RDS encrypted and private
# - VPC flow logs enabled

locals {
  environment = "production"
  project     = "efex-transfers"
}

# =============================================================================
# S3 BUCKETS - Secure Configuration
# =============================================================================

resource "aws_s3_bucket" "kyc_documents" {
  bucket = "efex-kyc-documents-prod"

  tags = {
    Name        = "EFEX KYC Documents"
    Environment = local.environment
    Compliance  = "CNBV-IFPE"
    DataClass   = "Confidential"
  }
}

# SECURE: Server-side encryption enabled
resource "aws_s3_bucket_server_side_encryption_configuration" "kyc_encryption" {
  bucket = aws_s3_bucket.kyc_documents.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.efex_key.arn
    }
    bucket_key_enabled = true
  }
}

# SECURE: Block ALL public access
resource "aws_s3_bucket_public_access_block" "kyc_public_access" {
  bucket = aws_s3_bucket.kyc_documents.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# SECURE: Versioning enabled for data recovery
resource "aws_s3_bucket_versioning" "kyc_versioning" {
  bucket = aws_s3_bucket.kyc_documents.id

  versioning_configuration {
    status = "Enabled"
  }
}

# SECURE: Lifecycle policy for compliance
resource "aws_s3_bucket_lifecycle_configuration" "kyc_lifecycle" {
  bucket = aws_s3_bucket.kyc_documents.id

  rule {
    id     = "archive-old-versions"
    status = "Enabled"

    noncurrent_version_transition {
      noncurrent_days = 30
      storage_class   = "GLACIER"
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }
}

# Transaction logs bucket - also secure
resource "aws_s3_bucket" "transaction_logs" {
  bucket = "efex-transaction-logs-prod"

  tags = {
    Name        = "EFEX Transaction Logs"
    Environment = local.environment
    DataClass   = "Confidential"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs_encryption" {
  bucket = aws_s3_bucket.transaction_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.efex_key.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs_public_access" {
  bucket = aws_s3_bucket.transaction_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# =============================================================================
# KMS - Encryption Key
# =============================================================================

resource "aws_kms_key" "efex_key" {
  description             = "EFEX data encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Name       = "EFEX Encryption Key"
    Compliance = "CNBV-IFPE"
  }
}

resource "aws_kms_alias" "efex_key_alias" {
  name          = "alias/efex-data-key"
  target_key_id = aws_kms_key.efex_key.key_id
}

# =============================================================================
# IAM POLICIES - Least Privilege
# =============================================================================

# SECURE: Specific actions only, no wildcards
resource "aws_iam_policy" "transfer_service_policy" {
  name        = "efex-transfer-service-policy"
  description = "Least privilege policy for EFEX transfer service"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3KYCAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.kyc_documents.arn,
          "${aws_s3_bucket.kyc_documents.arn}/*"
        ]
      },
      {
        Sid    = "KMSDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [aws_kms_key.efex_key.arn]
      },
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = ["${aws_cloudwatch_log_group.api_logs.arn}:*"]
      },
      {
        Sid    = "SecretsAccess"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:*:*:secret:efex/*"
        ]
      }
    ]
  })
}

# SECURE: Restricted trust policy
resource "aws_iam_role" "transfer_service_role" {
  name = "efex-transfer-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "transfer_service_attachment" {
  role       = aws_iam_role.transfer_service_role.name
  policy_arn = aws_iam_policy.transfer_service_policy.arn
}

data "aws_caller_identity" "current" {}

# =============================================================================
# VPC - Network Infrastructure
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"

  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "EFEX Production VPC"
  }
}

# SECURE: VPC Flow Logs enabled
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id

  tags = {
    Name = "EFEX VPC Flow Logs"
  }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/efex-flow-logs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.efex_key.arn
}

resource "aws_iam_role" "flow_log_role" {
  name = "efex-vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_log_policy" {
  name = "efex-vpc-flow-log-policy"
  role = aws_iam_role.flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# Private subnets for databases
resource "aws_subnet" "private_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false

  tags = {
    Name = "EFEX Private Subnet A"
    Type = "Private"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false

  tags = {
    Name = "EFEX Private Subnet B"
    Type = "Private"
  }
}

# =============================================================================
# SECURITY GROUPS - Restricted Access
# =============================================================================

# SECURE: API service only accessible from ALB
resource "aws_security_group" "api_service" {
  name        = "efex-api-service-sg"
  description = "Security group for EFEX API service"
  vpc_id      = aws_vpc.main.id

  # Only allow traffic from ALB
  ingress {
    description     = "HTTPS from ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "Database access"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.database.id]
  }

  tags = {
    Name = "EFEX API Security Group"
  }
}

# ALB security group
resource "aws_security_group" "alb" {
  name        = "efex-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "To API service"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.api_service.id]
  }

  tags = {
    Name = "EFEX ALB Security Group"
  }
}

# SECURE: Database only accessible from API service
resource "aws_security_group" "database" {
  name        = "efex-database-sg"
  description = "Security group for EFEX database"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "MySQL from API service only"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.api_service.id]
  }

  # No egress needed for RDS

  tags = {
    Name = "EFEX Database Security Group"
  }
}

# =============================================================================
# RDS - Secure Database
# =============================================================================

resource "aws_db_subnet_group" "main" {
  name       = "efex-db-subnet-group"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]

  tags = {
    Name = "EFEX DB Subnet Group"
  }
}

# SECURE: RDS with encryption, not public, with backups
resource "aws_db_instance" "transfers" {
  identifier     = "efex-transfers-db"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.medium"

  db_name  = "transfers"
  username = "efex_admin"
  # Password should come from Secrets Manager
  manage_master_user_password = true

  # SECURE: Encryption enabled
  storage_encrypted = true
  kms_key_id        = aws_kms_key.efex_key.arn

  # SECURE: Not publicly accessible
  publicly_accessible = false

  # SECURE: Deletion protection enabled
  deletion_protection = true

  # SECURE: Backup retention
  backup_retention_period = 30
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:00-Mon:05:00"

  # SECURE: Final snapshot required
  skip_final_snapshot       = false
  final_snapshot_identifier = "efex-transfers-final-${formatdate("YYYY-MM-DD", timestamp())}"

  # SECURE: Monitoring enabled
  performance_insights_enabled = true
  monitoring_interval          = 60
  monitoring_role_arn          = aws_iam_role.rds_monitoring.arn

  # Network
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]

  tags = {
    Name        = "EFEX Transfers Database"
    Environment = local.environment
    Compliance  = "CNBV-IFPE"
  }
}

resource "aws_iam_role" "rds_monitoring" {
  name = "efex-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# =============================================================================
# CLOUDWATCH - Encrypted Logging
# =============================================================================

# SECURE: Log group with KMS encryption
resource "aws_cloudwatch_log_group" "api_logs" {
  name = "/efex/api/logs"

  # SECURE: KMS encryption
  kms_key_id = aws_kms_key.efex_key.arn

  # Appropriate retention
  retention_in_days = 90

  tags = {
    Application = "EFEX API"
    Compliance  = "CNBV-IFPE"
  }
}

# =============================================================================
# ECR - Secure Container Registry
# =============================================================================

resource "aws_ecr_repository" "api" {
  name = "efex-api"

  # SECURE: Image scanning enabled
  image_scanning_configuration {
    scan_on_push = true
  }

  # SECURE: Immutable tags prevent overwriting
  image_tag_mutability = "IMMUTABLE"

  # SECURE: Encryption with KMS
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.efex_key.arn
  }

  tags = {
    Name = "EFEX API Repository"
  }
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
