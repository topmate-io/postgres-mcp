# Local Docker + Cloud Run Deployment Guide

## Overview

This guide explains how to deploy postgres-mcp to Cloud Run using local Docker with cross-platform build support. The deployment script (`deploy-cloud-run-local.sh`) handles everything: building the image for Linux/GCP (even on Mac), pushing to Google Container Registry, and deploying to Cloud Run.

## Prerequisites

1. **Docker Desktop** - Must be running
   - Download: https://www.docker.com/products/docker-desktop
   - Verify: `docker ps`

2. **gcloud CLI** - Authenticated with GCP
   - Install: https://cloud.google.com/sdk/docs/install
   - Verify: `gcloud auth list`

3. **Repository Files**
   - `Dockerfile.cloud-run-fixed` - Multi-stage build with Cloud SQL Proxy
   - `entrypoint.sh` - Startup orchestration script
   - `deploy-cloud-run-local.sh` - This deployment script

4. **GCP Configuration**
   - Project ID: `ds-dev-474406`
   - Secret Manager secret: `postgres-mcp-readonly-uri` (must already exist)
   - Service account: `1058307958897-compute@developer.gserviceaccount.com`

## What the Script Does

1. ✓ Verifies Docker is running
2. ✓ Verifies gcloud authentication
3. ✓ Configures Docker for Google Container Registry (GCR)
4. ✓ Builds Docker image using `buildx` (cross-platform for Mac → Linux/amd64)
5. ✓ Pushes image to Google Container Registry
6. ✓ Deploys image to Cloud Run with proper configuration
7. ✓ Verifies the service is running
8. ✓ Provides service URL and test commands

## Why buildx on Mac?

Mac's Docker Desktop runs on ARM64 (Apple Silicon) or x86_64 (Intel), but Cloud Run requires Linux x86_64 images. The script uses Docker's `buildx` feature to build for the correct architecture:

```bash
docker buildx build --platform linux/amd64 ...
```

This ensures the image works on Cloud Run regardless of your Mac's processor.

## Quick Start

### Method 1: One-Command Deployment

From the `postgres-mcp` directory:

```bash
cd /Users/dharsankumar/Documents/GitHub/postgres-mcp
./deploy-cloud-run-local.sh
```

That's it! The script handles everything.

### Method 2: Manual Steps

If you prefer to run commands manually:

```bash
# 1. Configure Docker for GCR
gcloud auth configure-docker gcr.io --quiet

# 2. Build image (cross-platform for linux/amd64)
docker buildx build \
  --platform linux/amd64 \
  -f Dockerfile.cloud-run-fixed \
  -t gcr.io/ds-dev-474406/postgres-mcp-proxy:latest \
  --load \
  .

# 3. Push to GCR
docker push gcr.io/ds-dev-474406/postgres-mcp-proxy:latest

# 4. Deploy to Cloud Run
gcloud run deploy postgres-mcp-readonly \
  --image=gcr.io/ds-dev-474406/postgres-mcp-proxy:latest \
  --region=asia-south1 \
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
  --project=ds-dev-474406
```

## Expected Execution Time

- Docker build: 5-8 minutes (first time), 2-3 minutes (cached)
- Push to GCR: 1-2 minutes
- Cloud Run deployment: 3-5 minutes
- **Total: ~10-15 minutes**

## Verification

### Check Service Status

```bash
gcloud run services describe postgres-mcp-readonly \
  --region=asia-south1 \
  --project=ds-dev-474406
```

### View Logs

```bash
gcloud run services logs read postgres-mcp-readonly \
  --region=asia-south1 \
  --project=ds-dev-474406 \
  --limit=50
```

### Test the Service

```bash
SERVICE_URL=$(gcloud run services describe postgres-mcp-readonly \
  --region=asia-south1 \
  --format='value(status.url)' \
  --project=ds-dev-474406)

curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" $SERVICE_URL
```

## Troubleshooting

### Docker: "Cannot connect to Docker daemon"
- Start Docker Desktop
- On Mac: Open Applications → Docker

### gcloud: "Property [core/project] not set"
```bash
gcloud config set project ds-dev-474406
```

### buildx: "no DOCKER_HOST" or builder error
```bash
# Create a new buildx builder
docker buildx create --use --name multiarch --driver docker-container
```

### Build fails with permission error
```bash
gcloud auth configure-docker gcr.io --quiet
```

### Cloud Run: "Health check timeout"
- Check logs: `gcloud run services logs read postgres-mcp-readonly --limit=50`
- This usually means the service is still starting. Wait 2-3 minutes and try again.
- If still failing, see next step.

### Cloud Run: "Failed to connect to Cloud SQL"
- Verify Secret Manager secret exists:
  ```bash
  gcloud secrets versions access latest \
    --secret=postgres-mcp-readonly-uri \
    --project=ds-dev-474406
  ```
- Verify service account has Cloud SQL Client role:
  ```bash
  gcloud projects get-iam-policy ds-dev-474406 \
    --flatten="bindings[].members" \
    --filter="bindings.members:1058307958897-compute*" \
    --format="table(bindings.role)"
  ```

## Architecture

```
Your Mac
  ↓
docker buildx build --platform linux/amd64
  ↓ (builds for Cloud Run's Linux environment)
Docker Image (gcr.io/.../postgres-mcp-proxy:latest)
  ↓
docker push to Google Container Registry
  ↓
gcloud run deploy (pulls image from GCR)
  ↓
Cloud Run Container (running linux/amd64)
  ├─ Cloud SQL Proxy (port 5432)
  └─ postgres-mcp (port 8000)
```

## Production Deployment

Once dev is working, use the same script for production with modified environment variables:

```bash
# Copy the script for production
cp deploy-cloud-run-local.sh deploy-cloud-run-prod.sh

# Edit for production:
# - PROJECT_ID="ds-share-474010" (production project)
# - SERVICE_NAME="postgres-mcp-readonly-prod"
# - Service account: (production service account)

./deploy-cloud-run-prod.sh
```

## Key Files

| File | Purpose |
|------|---------|
| `deploy-cloud-run-local.sh` | Main deployment script |
| `Dockerfile.cloud-run-fixed` | Multi-stage Docker build with Cloud SQL Proxy |
| `entrypoint.sh` | Container startup orchestration |
| `cloudbuild-cloud-run-proxy.yaml` | Cloud Build config (optional, for CI/CD) |

## More Information

- [Docker buildx documentation](https://docs.docker.com/build/buildx/)
- [Cloud Run deployment guide](https://cloud.google.com/run/docs/deploying)
- [Cloud SQL Proxy](https://cloud.google.com/sql/docs/mysql/cloud-sql-proxy)
