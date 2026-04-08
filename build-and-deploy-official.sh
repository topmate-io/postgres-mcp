#!/bin/bash
# Build and Deploy postgres-mcp to Cloud Run using official Docker image
set -e

PROJECT_ID="ds-share-474010"
REGION="asia-south1"
SERVICE_NAME="postgres-mcp"
SERVICE_ACCOUNT="49979260925-compute@developer.gserviceaccount.com"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}-official"

echo "=================================================="
echo "Building and Deploying postgres-mcp to Cloud Run"
echo "Using Official Docker Image"
echo "=================================================="
echo ""
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo ""

# Step 1: Build Docker image with platform flag
echo "Step 1: Building Docker image for linux/amd64..."
docker build --platform linux/amd64 -f Dockerfile.official -t ${IMAGE_NAME}:latest .

if [ $? -ne 0 ]; then
  echo "❌ Docker build failed!"
  exit 1
fi

echo "✓ Docker build successful!"
echo ""

# Step 2: Push to Google Container Registry
echo "Step 2: Pushing image to GCR..."
docker push ${IMAGE_NAME}:latest

if [ $? -ne 0 ]; then
  echo "❌ Docker push failed!"
  exit 1
fi

echo "✓ Image pushed to GCR!"
echo ""

# Step 3: Deploy to Cloud Run
echo "Step 3: Deploying to Cloud Run..."
gcloud run deploy $SERVICE_NAME \
  --image ${IMAGE_NAME}:latest \
  --region=$REGION \
  --platform managed \
  --cpu 2 \
  --memory 1Gi \
  --timeout 600 \
  --set-secrets DATABASE_URI=postgres-mcp-readonly-uri:latest \
  --add-cloudsql-instances $PROJECT_ID:$REGION:ds-share-pg \
  --set-env-vars ACCESS_MODE=restricted \
  --port 8000 \
  --no-allow-unauthenticated \
  --service-account=$SERVICE_ACCOUNT \
  --project=$PROJECT_ID

if [ $? -ne 0 ]; then
  echo "❌ Cloud Run deployment failed!"
  exit 1
fi

echo ""
echo "✓ Cloud Run deployment successful!"
echo ""

# Step 4: Get the service URL
SERVICE_URL=$(gcloud run services describe $SERVICE_NAME \
  --region=$REGION \
  --project=$PROJECT_ID \
  --format="value(status.url)")

echo "=================================================="
echo "Deployment Complete!"
echo "=================================================="
echo ""
echo "Service Name: $SERVICE_NAME"
echo "Service URL: $SERVICE_URL"
echo ""
echo "Next Steps:"
echo "1. Update cloud-run-mcp-postgres with the Cloud Run URL"
echo "2. Test connection with: ./cloud-run-mcp-postgres"
echo "3. Share with team members"
echo ""
echo "Grant team access with:"
echo "  gcloud projects add-iam-policy-binding $PROJECT_ID \\"
echo "    --member=\"user:EMAIL@example.com\" \\"
echo "    --role=\"roles/run.invoker\" \\"
echo "    --project=$PROJECT_ID"
echo ""
