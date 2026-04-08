#!/bin/bash
# Build and Deploy postgres-mcp to Cloud Run using Cloud Build
# Ensures the image is built for GCP/Linux architecture (not macOS)

set -e

PROJECT_ID="ds-share-474010"
REGION="asia-south1"
SERVICE_NAME="postgres-mcp"
SERVICE_ACCOUNT="49979260925-compute@developer.gserviceaccount.com"

echo "=================================================="
echo "Building and Deploying postgres-mcp to Cloud Run"
echo "=================================================="
echo ""
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Service: $SERVICE_NAME"
echo ""

# Step 1: Deploy to Cloud Run with source-based build
echo "Step 1: Building and deploying to Cloud Run..."
echo "(Cloud Run will build the Docker image and deploy automatically)"
echo ""

gcloud run deploy $SERVICE_NAME \
  --source . \
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
echo "1. Update cloud-run-proxy.sh with the Cloud Run URL:"
echo "   CLOUD_RUN_URL=\"${SERVICE_URL}/sse\""
echo ""
echo "2. Update your claude_desktop_config.json:"
echo "   \"command\": \"/path/to/cloud-run-proxy.sh\""
echo ""
echo "3. Run: gcloud auth login"
echo ""
echo "4. Restart Claude Desktop"
echo ""
echo "Test connection with:"
echo "   ./cloud-run-proxy.sh"
echo ""

# Step 5: Update cloud-run-proxy.sh if it exists
if [ -f "cloud-run-proxy.sh" ]; then
  echo "Updating cloud-run-proxy.sh with new Cloud Run URL..."

  # Backup original
  cp cloud-run-proxy.sh cloud-run-proxy.sh.bak

  # Update URL
  sed -i '' "s|CLOUD_RUN_URL=.*|CLOUD_RUN_URL=\"${SERVICE_URL}/sse\"|g" cloud-run-proxy.sh

  echo "✓ cloud-run-proxy.sh updated"
  echo "  Backup saved to: cloud-run-proxy.sh.bak"
else
  echo "⚠️  cloud-run-proxy.sh not found in current directory"
  echo "   Make sure to manually update it with the Cloud Run URL"
fi

echo ""
echo "=================================================="
