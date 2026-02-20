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
IMAGE_TAG=""  # Set during build; defaults to 'latest' via DEPLOY_IMAGE_TAG when --skip-build

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

  # Build topmate-db-mcp-server from its own repo (sibling directory)
  DB_MCP_REPO="${REPO_ROOT}/../topmate-db-mcp-server"
  if [ -d "${DB_MCP_REPO}" ] && [ -f "${DB_MCP_REPO}/Dockerfile" ]; then
    echo "Building topmate-db-mcp-server image from ${DB_MCP_REPO}..."
    docker buildx build \
      --platform linux/amd64 \
      -f "${DB_MCP_REPO}/Dockerfile" \
      -t "${DB_MCP_SERVER_IMAGE}:${IMAGE_TAG}" \
      -t "${DB_MCP_SERVER_IMAGE}:latest" \
      --push \
      "${DB_MCP_REPO}"
    echo "Pushed ${DB_MCP_SERVER_IMAGE}:${IMAGE_TAG}"
  else
    echo "WARNING: topmate-db-mcp-server repo not found at ${DB_MCP_REPO}."
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

  # Create topmate-bi-secrets (for BI MCP server: GitHub, GCP, S3, Redis)
  echo ""
  echo "Creating topmate-bi-secrets (optional keys)..."
  echo "  Secrets needed in AWS Secrets Manager (optional):"
  echo "    - topmate/bi-mcp/github-token"
  echo "    - topmate/bi-mcp/gcp-project-id"
  echo "    - topmate/bi-mcp/s3-bucket"
  echo "    - topmate/bi-mcp/redis-url"
  echo "    - topmate/bi-mcp/anthropic-api-key (for Claude API)"
  echo "    - topmate/bi-mcp/openai-api-key (for OpenAI)"
  echo "    - topmate/bi-mcp/openrouter-api-key (for OpenRouter)"
  echo ""

  BI_SECRET_ARGS=""

  # GitHub App credentials (preferred over PAT)
  GITHUB_APP_CREDS=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/github-app-credentials \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && {
    GITHUB_APP_ID=$(echo "${GITHUB_APP_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['app_id'])")
    GITHUB_INSTALL_ID=$(echo "${GITHUB_APP_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['installation_id'])")
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=github-app-id=${GITHUB_APP_ID}"
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=github-app-installation-id=${GITHUB_INSTALL_ID}"
    echo "  Found GitHub App credentials (app_id=${GITHUB_APP_ID}, installation_id=${GITHUB_INSTALL_ID})"
  } || echo "  WARN: topmate/bi-mcp/github-app-credentials not found"

  # Private key: write to temp file (PEM has newlines that break --from-literal)
  BI_SECRET_FILE_ARGS=""
  TMPDIR_SECRETS=$(mktemp -d)
  trap "rm -rf ${TMPDIR_SECRETS}" EXIT

  aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/github-app-private-key \
    --query SecretString --output text --region "${AWS_REGION}" \
    > "${TMPDIR_SECRETS}/github-app-private-key" 2>/dev/null && \
    BI_SECRET_FILE_ARGS="${BI_SECRET_FILE_ARGS} --from-file=github-app-private-key=${TMPDIR_SECRETS}/github-app-private-key" || \
    echo "  WARN: topmate/bi-mcp/github-app-private-key not found"

  GITHUB_WEBHOOK_SEC=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/github-webhook-secret \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=github-webhook-secret=${GITHUB_WEBHOOK_SEC}" || \
    echo "  WARN: topmate/bi-mcp/github-webhook-secret not found (webhook signature verification disabled)"

  # PAT fallback
  GITHUB_TOKEN=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/github-token \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=github-token=${GITHUB_TOKEN}" || \
    echo "  WARN: topmate/bi-mcp/github-token not found (GitHub PAT fallback disabled)"

  GCP_PROJECT_ID=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/gcp-project-id \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=gcp-project-id=${GCP_PROJECT_ID}" || \
    echo "  WARN: topmate/bi-mcp/gcp-project-id not found (Vertex AI will be disabled)"

  S3_BUCKET=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/s3-bucket \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=s3-bucket=${S3_BUCKET}" || \
    echo "  WARN: topmate/bi-mcp/s3-bucket not found (report uploads disabled)"

  REDIS_URL_BI=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/redis-url \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=redis-url=${REDIS_URL_BI}" || \
    echo "  WARN: topmate/bi-mcp/redis-url not found (using in-memory cache only)"

  # LLM API keys (only one needed depending on LLM_PROVIDER setting)
  ANTHROPIC_KEY=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/anthropic-api-key \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=anthropic-api-key=${ANTHROPIC_KEY}" || true

  OPENAI_KEY=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/openai-api-key \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=openai-api-key=${OPENAI_KEY}" || true

  OPENROUTER_KEY=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/openrouter-api-key \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=openrouter-api-key=${OPENROUTER_KEY}" || true

  # OAuth 2.1 secrets (Claude.ai Custom Connector)
  OAUTH_CLIENT_ID_VAL=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/oauth-client-id \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=oauth-client-id=${OAUTH_CLIENT_ID_VAL}" || \
    echo "  WARN: topmate/bi-mcp/oauth-client-id not found (OAuth disabled)"

  OAUTH_CLIENT_SECRET_VAL=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/oauth-client-secret \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=oauth-client-secret=${OAUTH_CLIENT_SECRET_VAL}" || true

  OAUTH_JWT_SECRET_VAL=$(aws secretsmanager get-secret-value \
    --secret-id topmate/bi-mcp/oauth-jwt-secret \
    --query SecretString --output text --region "${AWS_REGION}" 2>/dev/null) && \
    BI_SECRET_ARGS="${BI_SECRET_ARGS} --from-literal=oauth-jwt-secret=${OAUTH_JWT_SECRET_VAL}" || true

  if [ -n "${BI_SECRET_ARGS}" ] || [ -n "${BI_SECRET_FILE_ARGS}" ]; then
    eval kubectl create secret generic topmate-bi-secrets \
      ${BI_SECRET_ARGS} \
      ${BI_SECRET_FILE_ARGS} \
      -n "${NAMESPACE}" \
      --dry-run=client -o yaml | kubectl apply -f -
    echo "Kubernetes secret topmate-bi-secrets created/updated."
  else
    echo "  No BI secrets found. Creating empty secret placeholder."
    kubectl create secret generic topmate-bi-secrets \
      --from-literal=placeholder="none" \
      -n "${NAMESPACE}" \
      --dry-run=client -o yaml | kubectl apply -f -
  fi
else
  echo ""
  echo "[5/7] Skipping secrets creation (--skip-secrets)"
fi

# -----------------------------------------------------------------------------
# Step 5.5: Substitute Placeholders in Manifests
# -----------------------------------------------------------------------------
echo ""
echo "Substituting manifest placeholders..."
MANIFEST_DIR="${SCRIPT_DIR}/manifests/base"

# Default allowed IPs: VPC + localhost. Override with DEPLOY_ALLOWED_IPS env var.
ALLOWED_IPS="${DEPLOY_ALLOWED_IPS:-10.0.0.0/16,127.0.0.1,::1}"

# IMAGE_TAG may not be set if --skip-build was used
DEPLOY_IMAGE_TAG="${IMAGE_TAG:-latest}"

for f in "${MANIFEST_DIR}"/*.yaml; do
  sed -i.bak \
    -e "s|__AWS_ACCOUNT_ID__|${AWS_ACCOUNT_ID}|g" \
    -e "s|__IMAGE_TAG__|${DEPLOY_IMAGE_TAG}|g" \
    -e "s|__ALLOWED_IPS__|${ALLOWED_IPS}|g" \
    "$f"
done
# Clean up .bak files (macOS sed creates them with -i.bak)
rm -f "${MANIFEST_DIR}"/*.yaml.bak

# Ensure placeholders are restored even if kubectl fails (set -e exit)
trap 'echo "Restoring manifest placeholders..."; git -C "${REPO_ROOT}" checkout -- "${MANIFEST_DIR}"/*.yaml 2>/dev/null || true' EXIT

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

echo "Waiting for redis deployment..."
kubectl rollout status deployment/redis -n "${NAMESPACE}" --timeout=120s

echo "Waiting for postgres-mcp deployment..."
kubectl rollout status deployment/postgres-mcp -n "${NAMESPACE}" --timeout=300s

echo "Waiting for db-mcp-server deployment..."
kubectl rollout status deployment/db-mcp-server -n "${NAMESPACE}" --timeout=300s

# Restore is handled by EXIT trap (set after sed substitution)

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
echo "  curl http://${ALB_HOST}/bi-mcp/health"
echo ""
echo "Claude Desktop config:"
echo '  {'
echo '    "postgres-mcp-aws": {'
echo '      "command": "curl",'
echo "      \"args\": [\"-s\", \"-N\", \"http://mcp.gabbanext.run/postgres-mcp/sse\"]"
echo '    },'
echo '    "topmate-bi-mcp": {'
echo '      "command": "curl",'
echo "      \"args\": [\"-s\", \"-N\", \"http://mcp.gabbanext.run/bi-mcp/sse\"]"
echo '    }'
echo '  }'
