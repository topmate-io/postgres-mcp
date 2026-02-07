output "irsa_role_arn" {
  description = "IAM role ARN for the postgres-mcp service account (IRSA)"
  value       = aws_iam_role.postgres_mcp_sa.arn
}

output "ecr_repository_url" {
  description = "ECR repository URL for postgres-mcp"
  value       = aws_ecr_repository.postgres_mcp.repository_url
}

output "ecr_db_mcp_repository_url" {
  description = "ECR repository URL for topmate-db-mcp-server"
  value       = aws_ecr_repository.db_mcp_server.repository_url
}

output "cluster_name" {
  description = "EKS cluster name"
  value       = data.aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  description = "EKS cluster endpoint"
  value       = data.aws_eks_cluster.main.endpoint
}
