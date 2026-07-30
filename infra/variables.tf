# EFEX Infrastructure - Terraform Variables
# ==========================================

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name for tagging"
  type        = string
  default     = "efex-transfers"
}

# EFEX-VULN: Default values for sensitive variables
# These should come from secrets manager, not defaults
variable "db_username" {
  description = "Database master username"
  type        = string
  default     = "efex_admin"
}

variable "db_password" {
  description = "Database master password"
  type        = string
  default     = "efex_prod_password_2024!"  # VULNERABLE: Default password
  sensitive   = true
}
