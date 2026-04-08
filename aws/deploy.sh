#!/bin/bash
set -e

# ============================================
# Topmate PostgreSQL MCP Server - AWS Deployment
# ============================================

# Configuration - Update these values
AWS_REGION="${AWS_REGION:-us-east-1}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:-$(aws sts get-caller-identity --query Account --output text)}"
ECR_REPOSITORY="topmate-postgres-mcp"
ECS_CLUSTER="topmate-mcp-cluster"
ECS_SERVICE="topmate-postgres-mcp-service"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Database URI (set via environment or AWS Secrets Manager)
# DATABASE_URI="postgresql://user:pass@host:5432/dbname"

echo "=========================================="
echo "Deploying Topmate PostgreSQL MCP Server"
echo "=========================================="
echo "Region: $AWS_REGION"
echo "Account: $AWS_ACCOUNT_ID"
echo "Repository: $ECR_REPOSITORY"
echo "Cluster: $ECS_CLUSTER"
echo "Service: $ECS_SERVICE"
echo "Image Tag: $IMAGE_TAG"
echo "=========================================="

# Step 1: Create ECR repository if it doesn't exist
echo "Step 1: Checking ECR repository..."
aws ecr describe-repositories --repository-names $ECR_REPOSITORY --region $AWS_REGION 2>/dev/null || \
    aws ecr create-repository --repository-name $ECR_REPOSITORY --region $AWS_REGION

# Step 2: Login to ECR
echo "Step 2: Logging into ECR..."
aws ecr get-login-password --region $AWS_REGION | \
    docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# Step 3: Build Docker image
echo "Step 3: Building Docker image..."
docker build -f Dockerfile.aws -t $ECR_REPOSITORY:$IMAGE_TAG .

# Step 4: Tag and push to ECR
echo "Step 4: Pushing to ECR..."
docker tag $ECR_REPOSITORY:$IMAGE_TAG $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY:$IMAGE_TAG
docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY:$IMAGE_TAG

# Step 5: Create CloudWatch Log Group
echo "Step 5: Creating CloudWatch Log Group..."
aws logs create-log-group --log-group-name /ecs/topmate-postgres-mcp --region $AWS_REGION 2>/dev/null || true

# Step 6: Create/Update Task Definition
echo "Step 6: Registering ECS Task Definition..."
TASK_DEF=$(cat aws/task-definition.json | \
    sed "s/\${AWS_ACCOUNT_ID}/$AWS_ACCOUNT_ID/g" | \
    sed "s/\${AWS_REGION}/$AWS_REGION/g")

echo "$TASK_DEF" > /tmp/task-definition-resolved.json
aws ecs register-task-definition --cli-input-json file:///tmp/task-definition-resolved.json --region $AWS_REGION

# Step 7: Create ECS Cluster if it doesn't exist
echo "Step 7: Checking ECS Cluster..."
aws ecs describe-clusters --clusters $ECS_CLUSTER --region $AWS_REGION | grep -q "ACTIVE" || \
    aws ecs create-cluster --cluster-name $ECS_CLUSTER --region $AWS_REGION

# Step 8: Check if service exists and update or create
echo "Step 8: Deploying ECS Service..."
SERVICE_EXISTS=$(aws ecs describe-services --cluster $ECS_CLUSTER --services $ECS_SERVICE --region $AWS_REGION --query 'services[0].status' --output text 2>/dev/null || echo "NONE")

if [ "$SERVICE_EXISTS" == "ACTIVE" ]; then
    echo "Updating existing service..."
    aws ecs update-service \
        --cluster $ECS_CLUSTER \
        --service $ECS_SERVICE \
        --task-definition topmate-postgres-mcp \
        --force-new-deployment \
        --region $AWS_REGION
else
    echo "Service doesn't exist. Please create it using the AWS Console or aws-service.json"
    echo ""
    echo "To create the service, you'll need:"
    echo "1. A VPC with subnets"
    echo "2. A security group allowing inbound on port 8000"
    echo "3. (Optional) An Application Load Balancer"
    echo ""
    echo "Example command:"
    echo "aws ecs create-service \\"
    echo "    --cluster $ECS_CLUSTER \\"
    echo "    --service-name $ECS_SERVICE \\"
    echo "    --task-definition topmate-postgres-mcp \\"
    echo "    --desired-count 1 \\"
    echo "    --launch-type FARGATE \\"
    echo "    --network-configuration 'awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}' \\"
    echo "    --region $AWS_REGION"
fi

echo ""
echo "=========================================="
echo "Deployment Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Create a secret in AWS Secrets Manager:"
echo "   aws secretsmanager create-secret --name topmate/postgres-mcp/database-uri --secret-string 'postgresql://user:pass@host:5432/db'"
echo ""
echo "2. If service was just created, wait for tasks to start:"
echo "   aws ecs describe-services --cluster $ECS_CLUSTER --services $ECS_SERVICE"
echo ""
echo "3. Get the service endpoint (if using ALB) or task public IP"
echo ""
