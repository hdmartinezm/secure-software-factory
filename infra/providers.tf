# EFEX Infrastructure - Terraform Provider Configuration
# ======================================================

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend configuration for state management
  # In production, use S3 + DynamoDB for state locking
  # backend "s3" {
  #   bucket         = "efex-terraform-state"
  #   key            = "production/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "efex-terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "EFEX"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "Platform Team"
      Compliance  = "IFPE-CNBV"
    }
  }
}
