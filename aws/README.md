# AWS ECS Fargate Deployment Guide

Deploy the Topmate PostgreSQL MCP Server to AWS ECS Fargate.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AWS Cloud                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │   Claude    │───▶│     ALB     │───▶│  ECS Fargate    │  │
│  │   Desktop   │    │  (Optional) │    │  ┌───────────┐  │  │
│  └─────────────┘    └─────────────┘    │  │ postgres- │  │  │
│                                         │  │    mcp    │  │  │
│                                         │  └─────┬─────┘  │  │
│                                         └───────┼─────────┘  │
│                                                 │            │
│  ┌─────────────────┐    ┌─────────────────────┐│            │
│  │ Secrets Manager │    │   RDS PostgreSQL    │◀┘            │
│  │  (DATABASE_URI) │    │   (Read Replica)    │              │
│  └─────────────────┘    └─────────────────────┘              │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. AWS CLI configured with appropriate credentials
2. Docker installed locally
3. An AWS VPC with subnets
4. PostgreSQL database (RDS or external)

## Quick Start

### 1. Set Environment Variables

```bash
export AWS_REGION=ap-south-1
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

### 2. Create IAM Roles

```bash
# Create Task Execution Role
aws iam create-role \
    --role-name ecsTaskExecutionRole \
    --assume-role-policy-document file://aws/iam-policies.json#trustPolicy

aws iam attach-role-policy \
    --role-name ecsTaskExecutionRole \
    --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

# Create Task Role
aws iam create-role \
    --role-name ecsTaskRole \
    --assume-role-policy-document file://aws/iam-policies.json#trustPolicy
```

### 3. Create Secret for Database URI

```bash
aws secretsmanager create-secret \
    --name topmate/postgres-mcp/database-uri \
    --secret-string "postgresql://topmate_prod:PASSWORD@34.93.38.209:5432/topmate_db_prod" \
    --region $AWS_REGION
```

### 4. Deploy

```bash
chmod +x aws/deploy.sh
./aws/deploy.sh
```

### 5. Create ECS Service

After the deployment script runs, create the service:

```bash
# Replace with your actual subnet and security group IDs
aws ecs create-service \
    --cluster topmate-mcp-cluster \
    --service-name topmate-postgres-mcp-service \
    --task-definition topmate-postgres-mcp \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
    --region $AWS_REGION
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URI` | PostgreSQL connection string | Required |
| `PORT` | Server port | 8000 |
| `ACCESS_MODE` | `restricted` or `unrestricted` | restricted |
| `TRANSPORT` | `sse` or `stdio` | sse |

### Security Group Rules

Inbound:
- Port 8000 (TCP) from your IP or ALB

Outbound:
- Port 5432 (TCP) to PostgreSQL database
- Port 443 (HTTPS) for AWS services

## Connecting from Claude Desktop

Once deployed, update your Claude Desktop config to use the remote server:

```json
{
  "mcpServers": {
    "topmate-postgres": {
      "command": "npx",
      "args": [
        "-y",
        "@anthropic-ai/mcp-proxy",
        "http://<ECS_PUBLIC_IP>:8000/sse"
      ]
    }
  }
}
```

Or if using an ALB:

```json
{
  "mcpServers": {
    "topmate-postgres": {
      "command": "npx",
      "args": [
        "-y",
        "@anthropic-ai/mcp-proxy",
        "https://<ALB_DNS_NAME>/sse"
      ]
    }
  }
}
```

## Scaling

To scale the service:

```bash
aws ecs update-service \
    --cluster topmate-mcp-cluster \
    --service topmate-postgres-mcp-service \
    --desired-count 2
```

## Monitoring

### View Logs

```bash
aws logs tail /ecs/topmate-postgres-mcp --follow
```

### Check Service Status

```bash
aws ecs describe-services \
    --cluster topmate-mcp-cluster \
    --services topmate-postgres-mcp-service
```

## Costs (Estimated)

| Resource | Specification | Monthly Cost |
|----------|---------------|--------------|
| Fargate | 0.25 vCPU, 0.5GB | ~$10 |
| ALB (optional) | - | ~$20 |
| CloudWatch Logs | 1GB | ~$0.50 |
| **Total** | | **~$10-30** |

## Troubleshooting

### Task won't start

1. Check CloudWatch logs: `/ecs/topmate-postgres-mcp`
2. Verify secrets are accessible
3. Check security group allows outbound to database

### Can't connect from Claude Desktop

1. Verify ECS task has public IP or ALB is configured
2. Check security group allows inbound on port 8000
3. Test with: `curl http://<IP>:8000/health`

### Database connection errors

1. Verify DATABASE_URI secret value
2. Check security group allows outbound to port 5432
3. Verify database is accessible from VPC
