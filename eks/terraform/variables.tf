variable "cluster_name" {
  description = "Name of the existing EKS cluster"
  type        = string
  default     = "production-topmate-eks"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-1"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
  default     = "072528252688"
}

variable "app_namespace" {
  description = "Kubernetes namespace for postgres-mcp"
  type        = string
  default     = "postgres-mcp"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "ecr_repository_name" {
  description = "ECR repository name for the postgres-mcp image"
  type        = string
  default     = "topmate-postgres-mcp"
}

variable "ecr_db_mcp_repository_name" {
  description = "ECR repository name for the topmate-db-mcp-server image"
  type        = string
  default     = "topmate-db-mcp-server"
}
