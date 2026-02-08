#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Deploy postgres-mcp + topmate-db-mcp-server to AWS EKS
# =============================================================================
# Usage: ./deploy.sh [--skip-build] [--skip-terraform] [--skip-secrets]
#
# Prerequisites:
#   - AWS CLI configured with profile 072528252688_AWSAdministratorAccess
#   - kubectl installed
#   - docker installed (with buildx for multi-platform)
#   - terraform installed
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configuration
AWS_ACCOUNT_ID="072528252688"
AWS_REGION="ap-south-1"
AWS_PROFILE="topmate-prod"
EKS_CLUSTER="production-topmate-eks"
NAMESPACE="postgres-mcp"
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
POSTGRES_MCP_IMAGE="${ECR_REGISTRY}/topmate-postgres-mcp"
DB_MCP_SERVER_IMAGE="${ECR_REGISTRY}/topmate-db-mcp-server"

# Parse flags
SKIP_BUILD=false
SKIP_TERRAFORM=false
SKIP_SECRETS=false

for arg in "$@"; do
  case $arg in
    --skip-build) SKIP_BUILD=true ;;
    --skip-terraform) SKIP_TERRAFORM=true ;;
    --skip-secrets) SKIP_SECRETS=true ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

echo "============================================="
echo " Deploying postgres-mcp to EKS"
echo "============================================="
echo " Cluster:  ${EKS_CLUSTER}"
echo " Region:   ${AWS_REGION}"
echo " Registry: ${ECR_REGISTRY}"
echo "============================================="

# -----------------------------------------------------------------------------
# Step 1: AWS Authentication
# -----------------------------------------------------------------------------
echo ""
echo "[1/7] Authenticating with AWS..."
export AWS_PROFILE="${AWS_PROFILE}"
aws sts get-caller-identity --output text || {
  echo "ERROR: AWS authentication failed. Ensure profile '${AWS_PROFILE}' is configured."
  exit 1
}

# Configure kubectl
echo "Configuring kubectl for ${EKS_CLUSTER}..."
aws eks update-kubeconfig \
  --name "${EKS_CLUSTER}" \
  --region "${AWS_REGION}" \
  --alias "${EKS_CLUSTER}"

# Authenticate Docker to ECR
echo "Authenticating Docker to ECR..."
aws ecr get-login-password --region "${AWS_REGION}" | \
  docker login --username AWS --password-stdin "${ECR_REGISTRY}"

# -----------------------------------------------------------------------------
# Step 2: Terraform (IRSA + ECR)
# -----------------------------------------------------------------------------
if [ "$SKIP_TERRAFORM" = false ]; then
  echo ""
  echo "[2/7] Applying Terraform (IRSA + ECR)..."
  cd "${SCRIPT_DIR}/terraform"
  terraform init
  terraform plan -out=tfplan
  terraform apply tfplan
  rm -f tfplan
  cd "${SCRIPT_DIR}"
else
  echo ""
  echo "[2/7] Skipping Terraform (--skip-terraform)"
fi

# -----------------------------------------------------------------------------
# Step 3: Build and Push Docker Images
# -----------------------------------------------------------------------------
if [ "$SKIP_BUILD" = false ]; then
  echo ""
  echo "[3/7] Building and pushing Docker images..."

  IMAGE_TAG="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)-$(date +%Y%m%d%H%M%S)"

  # Build postgres-mcp
  echo "Building postgres-mcp image..."
  docker buildx build \
    --platform linux/amd64 \
    -f "${REPO_ROOT}/Dockerfile.aws" \
    -t "${POSTGRES_MCP_IMAGE}:${IMAGE_TAG}" \
    -t "${POSTGRES_MCP_IMAGE}:latest" \
    --push \
    "${REPO_ROOT}"

  echo "Pushed ${POSTGRES_MCP_IMAGE}:${IMAGE_TAG}"

  # Build topmate-db-mcp-server (if Dockerfile exists in repo)
  if [ -f "${REPO_ROOT}/Dockerfile.db-mcp-server" ]; then
    echo "Building topmate-db-mcp-server image..."
    docker buildx build \
      --platform linux/amd64 \
      -f "${REPO_ROOT}/Dockerfile.db-mcp-server" \
      -t "${DB_MCP_SERVER_IMAGE}:${IMAGE_TAG}" \
      -t "${DB_MCP_SERVER_IMAGE}:latest" \
      --push \
      "${REPO_ROOT}"
    echo "Pushed ${DB_MCP_SERVER_IMAGE}:${IMAGE_TAG}"
  else
    echo "WARNING: Dockerfile.db-mcp-server not found. Skipping db-mcp-server build."
    echo "         Build and push the image separately before deploying."
  fi
else
  echo ""
  echo "[3/7] Skipping Docker build (--skip-build)"
fi

# -----------------------------------------------------------------------------
# Step 4: Create Namespace
# -----------------------------------------------------------------------------
echo ""
echo "[4/7] Creating namespace (if not exists)..."
kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -

# -----------------------------------------------------------------------------
# Step 5: Create Secrets from AWS Secrets Manager
# -----------------------------------------------------------------------------
if [ "$SKIP_SECRETS" = false ]; then
  echo ""
  echo "[5/7] Creating Kubernetes secrets from AWS Secrets Manager..."
  echo ""
  echo "NOTE: Ensure the following secrets exist in AWS Secrets Manager:"
  echo "  - topmate/postgres-mcp/database-uri"
  echo "  - topmate/postgres-mcp/logic-hub-url"
  echo "  - topmate/postgres-mcp/logic-hub-api-key"
  echo ""
  echo "To create them manually:"
  echo "  aws secretsmanager create-secret --name topmate/postgres-mcp/database-uri \\"
  echo "    --secret-string 'postgresql://user:pass@<RDS_READ_REPLICA>:5432/topmate_db_prod' --region ${AWS_REGION}"
  echo "  aws secretsmanager create-secret --name topmate/postgres-mcp/logic-hub-url \\"
  echo "    --secret-string '<TOPMATE_LOGIC_HUB_BASE_URL>' --region ${AWS_REGION}"
  echo "  aws secretsmanager create-secret --name topmate/postgres-mcp/logic-hub-api-key \\"
  echo "    --secret-string '<TOPMATE_LOGIC_HUB_API_KEY>' --region ${AWS_REGION}"
  echo ""

  # Fetch secrets and create Kubernetes secret
  DATABASE_URI=$(aws secretsmanager get-secret-value \
    --secret-id topmate/postgres-mcp/database-uri \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) || {
    echo "ERROR: Could not fetch topmate/postgres-mcp/database-uri from Secrets Manager."
    echo "       Create the secret first, then re-run or use --skip-secrets."
    exit 1
  }

  LOGIC_HUB_URL=$(aws secretsmanager get-secret-value \
    --secret-id topmate/postgres-mcp/logic-hub-url \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) || {
    echo "ERROR: Could not fetch topmate/postgres-mcp/logic-hub-url from Secrets Manager."
    exit 1
  }

  LOGIC_HUB_API_KEY=$(aws secretsmanager get-secret-value \
    --secret-id topmate/postgres-mcp/logic-hub-api-key \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) || {
    echo "ERROR: Could not fetch topmate/postgres-mcp/logic-hub-api-key from Secrets Manager."
    exit 1
  }

  kubectl create secret generic postgres-mcp-secrets \
    --from-literal=database-uri="${DATABASE_URI}" \
    --from-literal=logic-hub-url="${LOGIC_HUB_URL}" \
    --from-literal=logic-hub-api-key="${LOGIC_HUB_API_KEY}" \
    -n "${NAMESPACE}" \
    --dry-run=client -o yaml | kubectl apply -f -

  echo "Kubernetes secret postgres-mcp-secrets created/updated."
else
  echo ""
  echo "[5/7] Skipping secrets creation (--skip-secrets)"
fi

# -----------------------------------------------------------------------------
# Step 6: Apply Kustomize Manifests
# -----------------------------------------------------------------------------
echo ""
echo "[6/7] Applying Kubernetes manifests..."
kubectl apply -k "${SCRIPT_DIR}/manifests/overlays/production"

# -----------------------------------------------------------------------------
# Step 7: Wait for Rollout
# -----------------------------------------------------------------------------
echo ""
echo "[7/7] Waiting for deployments to roll out..."

echo "Waiting for postgres-mcp deployment..."
kubectl rollout status deployment/postgres-mcp -n "${NAMESPACE}" --timeout=300s

echo "Waiting for db-mcp-server deployment..."
kubectl rollout status deployment/db-mcp-server -n "${NAMESPACE}" --timeout=300s

# -----------------------------------------------------------------------------
# Verification
# -----------------------------------------------------------------------------
echo ""
echo "============================================="
echo " Deployment Complete!"
echo "============================================="
echo ""
echo "Pods:"
kubectl get pods -n "${NAMESPACE}" -o wide
echo ""
echo "Services:"
kubectl get svc -n "${NAMESPACE}"
echo ""
echo "Ingress:"
kubectl get ingress -n "${NAMESPACE}"
echo ""

ALB_HOST=$(kubectl get ingress postgres-mcp-ingress -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "<pending>")
echo "ALB Endpoint: ${ALB_HOST}"
echo ""
echo "Verify endpoints:"
echo "  curl http://${ALB_HOST}/postgres-mcp/health"
echo "  curl -N http://${ALB_HOST}/postgres-mcp/sse"
echo "  curl http://${ALB_HOST}/db-mcp/health"
echo ""
echo "Claude Desktop config:"
echo '  {'
echo '    "postgres-mcp-aws": {'
echo '      "command": "curl",'
echo "      \"args\": [\"-s\", \"-N\", \"http://mcp.gabbanext.run/postgres-mcp/sse\"]"
echo '    },'
echo '    "topmate-db-mcp-aws": {'
echo '      "command": "curl",'
echo "      \"args\": [\"-s\", \"-N\", \"http://mcp.gabbanext.run/db-mcp/sse\"]"
echo '    }'
echo '  }'
