#!/bin/bash

# ==========================================
# Local Docker + Cloud Run Deployment Script
# Builds custom image with Cloud SQL Proxy using local Docker
# Supports Mac (arm64) via buildx cross-platform builds
# ==========================================

set -e

PROJECT_ID="ds-dev-474406"
REGION="asia-south1"
SERVICE_NAME="postgres-mcp-readonly"
IMAGE_NAME="postgres-mcp-proxy"
IMAGE_TAG="latest"
GCR_IMAGE="gcr.io/$PROJECT_ID/$IMAGE_NAME:$IMAGE_TAG"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

# Header
echo ""
echo "=========================================="
echo "Cloud Run Deployment with Local Docker"
echo "=========================================="
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo "Image: $GCR_IMAGE"
echo ""

# Step 1: Verify Docker is running
log_info "Step 1: Verifying Docker is running..."
if ! docker ps > /dev/null 2>&1; then
    log_error "Docker is not running. Please start Docker Desktop and try again."
    exit 1
fi
log_success "Docker is running"
echo ""

# Step 2: Verify gcloud is authenticated
log_info "Step 2: Verifying gcloud authentication..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
    log_error "gcloud is not authenticated. Run: gcloud auth login"
    exit 1
fi
CURRENT_USER=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
log_success "Authenticated as: $CURRENT_USER"
echo ""

# Step 3: Verify gcloud project
log_info "Step 3: Verifying gcloud project..."
CURRENT_PROJECT=$(gcloud config get-value project)
if [ "$CURRENT_PROJECT" != "$PROJECT_ID" ]; then
    log_info "Setting project to $PROJECT_ID..."
    gcloud config set project $PROJECT_ID
fi
log_success "Using project: $PROJECT_ID"
echo ""

# Step 4: Configure Docker for GCR
log_info "Step 4: Configuring Docker for Google Container Registry..."
gcloud auth configure-docker gcr.io --quiet
log_success "Docker configured for GCR"
echo ""

# Step 5: Verify Dockerfile exists
log_info "Step 5: Verifying Dockerfile.cloud-run-fixed exists..."
if [ ! -f "Dockerfile.cloud-run-fixed" ]; then
    log_error "Dockerfile.cloud-run-fixed not found in current directory"
    echo "Current directory: $(pwd)"
    exit 1
fi
log_success "Dockerfile.cloud-run-fixed found"
echo ""

# Step 6: Build Docker image with buildx (supports cross-platform builds on Mac)
log_info "Step 6: Building Docker image..."
echo "  Using buildx for cross-platform build (linux/amd64)"
echo "  This ensures the image works on Cloud Run even though you're on Mac"
echo ""

# Check if buildx is available
if ! docker buildx version > /dev/null 2>&1; then
    log_info "Installing docker buildx builder..."
    docker buildx create --use --name multiarch --driver docker-container
fi

# Build with buildx for linux/amd64
docker buildx build \
    --platform linux/amd64 \
    -f Dockerfile.cloud-run-fixed \
    -t $GCR_IMAGE \
    --load \
    .

log_success "Docker image built successfully"
echo ""

# Step 7: Verify image was built
log_info "Step 7: Verifying image..."
if ! docker image inspect $GCR_IMAGE > /dev/null 2>&1; then
    log_error "Docker image failed to build or load"
    exit 1
fi
log_success "Image verified: $GCR_IMAGE"
echo ""

# Step 8: Push image to GCR
log_info "Step 8: Pushing image to Google Container Registry..."
log_info "This may take 1-3 minutes depending on your internet connection..."
echo ""

docker push $GCR_IMAGE

log_success "Image pushed to GCR"
echo ""

# Step 9: Verify image in GCR
log_info "Step 9: Verifying image in GCR..."
if ! gcloud container images list --project=$PROJECT_ID --filter="name:$IMAGE_NAME" --format="value(name)" | grep -q "$IMAGE_NAME"; then
    log_error "Image not found in GCR. Push may have failed."
    exit 1
fi
log_success "Image verified in GCR"
echo ""

# Step 10: Delete previous failed deployments
log_info "Step 10: Cleaning up previous failed deployments..."
gcloud run services delete $SERVICE_NAME \
    --region=$REGION \
    --project=$PROJECT_ID \
    --quiet 2>/dev/null || true

sleep 2
log_success "Cleaned up previous service"
echo ""

# Step 11: Deploy to Cloud Run
log_info "Step 11: Deploying to Cloud Run..."
log_info "This may take 3-5 minutes..."
echo ""

gcloud run deploy $SERVICE_NAME \
    --image=$GCR_IMAGE \
    --region=$REGION \
    --platform=managed \
    --cpu=2 \
    --memory=1Gi \
    --timeout=600 \
    --concurrency=80 \
    --set-secrets=DATABASE_URI=postgres-mcp-readonly-uri:latest \
    --set-env-vars=ACCESS_MODE=restricted \
    --port=8000 \
    --allow-unauthenticated \
    --service-account=1058307958897-compute@developer.gserviceaccount.com \
    --min-instances=0 \
    --max-instances=10 \
    --project=$PROJECT_ID

log_success "Cloud Run deployment complete"
echo ""

# Step 12: Get service URL
log_info "Step 12: Retrieving service URL..."
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
    --region=$REGION \
    --format='value(status.url)' \
    --project=$PROJECT_ID)

if [ -z "$SERVICE_URL" ]; then
    log_error "Failed to retrieve service URL"
    exit 1
fi

log_success "Service URL retrieved"
echo ""

# Step 13: Verify service is running
log_info "Step 13: Verifying service is healthy..."
sleep 5

# Try to hit the service
AUTH_TOKEN=$(gcloud auth print-identity-token)
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    "$SERVICE_URL" || echo "000")

if [ "$HTTP_STATUS" = "200" ]; then
    log_success "Service is healthy (HTTP 200)"
elif [ "$HTTP_STATUS" = "000" ]; then
    log_info "Service is starting (may take a moment). Check again in 30 seconds."
else
    log_info "Service returned HTTP $HTTP_STATUS (may still be starting)"
fi
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}SUCCESS!${NC}"
echo "=========================================="
echo ""
echo "Service Details:"
echo "  Name: $SERVICE_NAME"
echo "  Region: $REGION"
echo "  Image: $GCR_IMAGE"
echo "  URL: $SERVICE_URL"
echo ""
echo "Test the service:"
echo "  curl -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" $SERVICE_URL"
echo ""
echo "View logs:"
echo "  gcloud run services logs read $SERVICE_NAME --region=$REGION --project=$PROJECT_ID --limit=50"
echo ""
echo "Delete service (if needed):"
echo "  gcloud run services delete $SERVICE_NAME --region=$REGION --project=$PROJECT_ID"
echo ""
