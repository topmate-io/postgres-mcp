#!/bin/bash

# Deploy postgres-mcp with Cloud SQL Proxy to Cloud Run
# This script builds the Docker image with Cloud SQL Proxy sidecar and deploys it

set -e

PROJECT_ID="ds-dev-474406"
REGION="asia-south1"
SERVICE_NAME="postgres-mcp-readonly"

echo "=========================================="
echo "Deploying postgres-mcp to Cloud Run"
echo "=========================================="
echo ""
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo ""

# Step 1: Build with Cloud Build
echo "Step 1: Building Docker image with Cloud Build..."
echo ""

gcloud builds submit \
  --config=cloudbuild-cloud-run-proxy.yaml \
  --project=$PROJECT_ID

echo ""
echo "✓ Docker image built and pushed to GCR"
echo ""

# Step 2: Deploy to Cloud Run
echo "Step 2: Deploying to Cloud Run..."
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
echo "✓ Deployment complete!"
echo ""

# Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
  --region=$REGION \
  --format='value(status.url)' \
  --project=$PROJECT_ID)

echo "=========================================="
echo "Service deployed successfully!"
echo "=========================================="
echo "Service URL: $SERVICE_URL"
echo ""
echo "Test the service:"
echo "  curl -H \"Authorization: Bearer \$(gcloud auth print-identity-token)\" $SERVICE_URL"
echo ""
