#!/bin/bash

# ========================================
# COMPLETE CLOUD SHELL DEPLOYMENT SCRIPT
# Copy-paste this entire script into Cloud Shell
# ========================================

set -e

PROJECT_ID="ds-dev-474406"
REGION="asia-south1"
SERVICE_NAME="postgres-mcp-readonly"

echo "=========================================="
echo "Cloud Run Deployment"
echo "=========================================="
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo ""

# Step 1: Clone and setup
echo "Step 1: Cloning repository..."
cd ~
rm -rf postgres-mcp
git clone https://github.com/topmate-io/postgres-mcp.git
cd postgres-mcp
git pull origin main

echo "✓ Repository ready"
echo ""

# Step 2: Configure Docker
echo "Step 2: Configuring Docker for GCR..."
gcloud auth configure-docker gcr.io --quiet
echo "✓ Docker configured"
echo ""

# Step 3: Build Docker image
echo "Step 3: Building Docker image with Cloud SQL Proxy..."
echo "This will take 3-5 minutes..."
echo ""

docker build -f Dockerfile.cloud-run-fixed \
  -t gcr.io/$PROJECT_ID/postgres-mcp-proxy:latest \
  -t gcr.io/$PROJECT_ID/postgres-mcp-proxy:$(date +%s) \
  .

echo ""
echo "✓ Docker image built successfully"
echo ""

# Step 4: Push to GCR
echo "Step 4: Pushing image to Google Container Registry..."
docker push gcr.io/$PROJECT_ID/postgres-mcp-proxy:latest

echo ""
echo "✓ Image pushed to GCR"
echo ""

# Step 5: Deploy to Cloud Run
echo "Step 5: Deploying to Cloud Run..."
echo "This will take 2-3 minutes..."
echo ""

gcloud run deploy $SERVICE_NAME \
  --image=gcr.io/$PROJECT_ID/postgres-mcp-proxy:latest \
  --region=$REGION \
  --platform=managed \
  --cpu=2 \
  --memory=1Gi \
  --timeout=600 \
  --concurrency=80 \
  --set-secrets=DATABASE_URI=postgres-mcp-readonly-uri:latest \
  --set-env-vars=ACCESS_MODE=restricted \
  --port=8000 \
  --no-allow-unauthenticated \
  --service-account=1058307958897-compute@developer.gserviceaccount.com \
  --project=$PROJECT_ID

echo ""
echo "✓ Cloud Run deployment complete!"
echo ""

# Step 6: Get service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
  --region=$REGION \
  --format='value(status.url)' \
  --project=$PROJECT_ID)

echo "=========================================="
echo "SUCCESS!"
echo "=========================================="
echo ""
echo "Service URL: $SERVICE_URL"
echo ""
echo "Test the service:"
echo "  curl -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" $SERVICE_URL"
echo ""
echo "View logs:"
echo "  gcloud run services logs read $SERVICE_NAME --region=$REGION --project=$PROJECT_ID --limit=50"
echo ""
echo "=========================================="
