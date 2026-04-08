# IRSA role for postgres-mcp service account
# Allows pods to access AWS Secrets Manager and CloudWatch Logs

locals {
  oidc_issuer = replace(data.aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")
}

# Trust policy: allow the postgres-mcp service account to assume this role
data "aws_iam_policy_document" "postgres_mcp_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.eks.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer}:sub"
      values   = ["system:serviceaccount:${var.app_namespace}:postgres-mcp-sa"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_issuer}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "postgres_mcp_sa" {
  name               = "postgres-mcp-sa-role"
  assume_role_policy = data.aws_iam_policy_document.postgres_mcp_assume_role.json

  tags = {
    Name = "postgres-mcp-sa-role"
  }
}

# Secrets Manager access policy (postgres-mcp + bi-mcp secrets)
data "aws_iam_policy_document" "secrets_access" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [
      "arn:aws:secretsmanager:${var.region}:${var.aws_account_id}:secret:topmate/postgres-mcp/*",
      "arn:aws:secretsmanager:${var.region}:${var.aws_account_id}:secret:topmate/bi-mcp/*",
    ]
  }
}

# S3 access policy for BI MCP report uploads
data "aws_iam_policy_document" "s3_access" {
  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      "arn:aws:s3:::${var.bi_mcp_s3_bucket}",
      "arn:aws:s3:::${var.bi_mcp_s3_bucket}/*",
    ]
  }
}

resource "aws_iam_policy" "s3_access" {
  name   = "postgres-mcp-s3-access"
  policy = data.aws_iam_policy_document.s3_access.json
}

resource "aws_iam_role_policy_attachment" "s3_access" {
  role       = aws_iam_role.postgres_mcp_sa.name
  policy_arn = aws_iam_policy.s3_access.arn
}

resource "aws_iam_policy" "secrets_access" {
  name   = "postgres-mcp-secrets-access"
  policy = data.aws_iam_policy_document.secrets_access.json
}

resource "aws_iam_role_policy_attachment" "secrets_access" {
  role       = aws_iam_role.postgres_mcp_sa.name
  policy_arn = aws_iam_policy.secrets_access.arn
}

# CloudWatch Logs access policy
data "aws_iam_policy_document" "cloudwatch_logs" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = [
      "arn:aws:logs:${var.region}:${var.aws_account_id}:log-group:/eks/postgres-mcp:*",
    ]
  }
}

resource "aws_iam_policy" "cloudwatch_logs" {
  name   = "postgres-mcp-cloudwatch-logs"
  policy = data.aws_iam_policy_document.cloudwatch_logs.json
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs" {
  role       = aws_iam_role.postgres_mcp_sa.name
  policy_arn = aws_iam_policy.cloudwatch_logs.arn
}
