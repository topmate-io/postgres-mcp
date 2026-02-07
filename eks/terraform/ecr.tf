# ECR repository for postgres-mcp image
resource "aws_ecr_repository" "postgres_mcp" {
  name                 = var.ecr_repository_name
  image_tag_mutability = "MUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = var.ecr_repository_name
  }
}

# ECR repository for topmate-db-mcp-server image
resource "aws_ecr_repository" "db_mcp_server" {
  name                 = var.ecr_db_mcp_repository_name
  image_tag_mutability = "MUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = var.ecr_db_mcp_repository_name
  }
}

# Lifecycle policy: keep last 10 images
resource "aws_ecr_lifecycle_policy" "postgres_mcp" {
  repository = aws_ecr_repository.postgres_mcp.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

resource "aws_ecr_lifecycle_policy" "db_mcp_server" {
  repository = aws_ecr_repository.db_mcp_server.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}
