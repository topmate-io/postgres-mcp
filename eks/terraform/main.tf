terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket  = "topmate-terraform-state"
    key     = "eks/postgres-mcp/terraform.tfstate"
    region  = "ap-south-1"
    encrypt = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Environment = var.environment
      Application = "postgres-mcp"
      ManagedBy   = "terraform"
    }
  }
}

# Reference existing EKS cluster
data "aws_eks_cluster" "main" {
  name = var.cluster_name
}

# Reference existing OIDC provider for IRSA
data "aws_iam_openid_connect_provider" "eks" {
  url = data.aws_eks_cluster.main.identity[0].oidc[0].issuer
}
