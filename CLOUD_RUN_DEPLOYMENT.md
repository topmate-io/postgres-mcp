# Cloud Run Deployment Guide

## Problem Solved

The Cloud Run startup timeout was caused by:
1. **Official postgres-mcp image lacks Cloud SQL Proxy** - can't establish Unix socket connections
2. **Database credentials were incorrect** - the `mcp_readonly` user wasn't created

## Solution: Cloud SQL Proxy Sidecar Pattern

We've created a custom Docker setup that runs:
1. **Cloud SQL Proxy** (connects to Cloud SQL, listens on localhost:5432)
2. **postgres-mcp** (connects to localhost:5432)

This solves the startup timeout issue!

## Deployment Steps (Execute from Cloud Shell)

### Step 1: Clone the repo in Cloud Shell

```bash
# Go to Cloud Shell
cd ~

# Clone the postgres-mcp repo (if not already cloned)
git clone https://github.com/crystaldba/postgres-mcp.git
cd postgres-mcp

# Checkout or pull latest code
git pull origin main
```

### Step 2: Copy the new files from your local repo

Copy these files from your local machine to Cloud Shell:
- `entrypoint.sh`
- `Dockerfile.cloud-run-fixed`
- `cloudbuild-cloud-run-proxy.yaml`

Or use git to commit and push:

```bash
# From your local machine
cd /Users/dharsankumar/Documents/GitHub/postgres-mcp
git add entrypoint.sh Dockerfile.cloud-run-fixed cloudbuild-cloud-run-proxy.yaml
git commit -m "Add Cloud SQL Proxy sidecar for Cloud Run deployment"
git push origin main

# Then in Cloud Shell:
cd ~/postgres-mcp && git pull origin main
```

### Step 3: Build and Push to GCR (from Cloud Shell)

```bash
# In Cloud Shell
cd ~/postgres-mcp

PROJECT_ID="ds-dev-474406"

echo "Configuring Docker for GCR..."
gcloud auth configure-docker gcr.io --quiet

echo "Building Docker image..."
docker build -f Dockerfile.cloud-run-fixed \
  -t gcr.io/$PROJECT_ID/postgres-mcp-proxy:latest \
  .

echo "Pushing to Google Container Registry..."
docker push gcr.io/$PROJECT_ID/postgres-mcp-proxy:latest

echo "✓ Image pushed successfully!"
```

### Step 4: Deploy to Cloud Run (from Cloud Shell)

```bash
# In Cloud Shell
gcloud run deploy postgres-mcp-readonly \
  --image=gcr.io/$PROJECT_ID/postgres-mcp-proxy:latest \
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
  --project=$PROJECT_ID

echo "✓ Cloud Run deployment complete!"
```

### Step 5: Test the Deployment

```bash
# In Cloud Shell
SERVICE_URL=$(gcloud run services describe postgres-mcp-readonly \
  --region=asia-south1 \
  --format='value(status.url)' \
  --project=$PROJECT_ID)

echo "Service URL: $SERVICE_URL"

# Test health endpoint
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "$SERVICE_URL" 2>&1 | head -50
```

## Expected Success Indicators

When Cloud Run starts successfully, you should see:

✅ Service is in "Running" state
✅ Health checks pass
✅ Logs show:
  ```
  === postgres-mcp Cloud Run Startup ===
  Starting Cloud SQL Proxy...
  ✓ Cloud SQL Proxy started
  Waiting for Cloud SQL Proxy to be ready...
  Starting postgres-mcp...
  ✓ postgres-mcp started
  ```

## Troubleshooting

### Cloud Run still timing out?

Check the logs:
```bash
gcloud run services logs read postgres-mcp-readonly \
  --region=asia-south1 \
  --project=ds-dev-474406 \
  --limit=50
```

### Database authentication failed?

Verify the Secret Manager secret has correct credentials:
```bash
gcloud secrets versions access latest \
  --secret=postgres-mcp-readonly-uri \
  --project=ds-dev-474406
```

Should show:
```
postgresql://mcp_readonly:SecurePassword123!MCP@db.example.com/topmate_db_new
```

### Can't push to GCR?

Make sure Docker is running in Cloud Shell and you're authenticated:
```bash
gcloud auth configure-docker gcr.io --quiet
docker push gcr.io/ds-dev-474406/postgres-mcp-proxy:latest
```

## Files Created

- **`entrypoint.sh`** - Startup script that runs Cloud SQL Proxy + postgres-mcp
- **`Dockerfile.cloud-run-fixed`** - Multi-stage Dockerfile with Cloud SQL Proxy included
- **`cloudbuild-cloud-run-proxy.yaml`** - Cloud Build configuration (optional, for automated builds)

## Architecture

```
Cloud Run Container
├── Cloud SQL Proxy (background)
│   └── Listens on 127.0.0.1:5432
└── postgres-mcp (foreground)
    └── Connects to 127.0.0.1:5432
```

This ensures:
✅ No timeout waiting for Cloud SQL connection
✅ postgres-mcp connects via local proxy
✅ All Cloud SQL IAM authentication handled by proxy
✅ Read-only enforcement via mcp_readonly user
✅ Multiple team members can connect via single Cloud Run service

## Next: Team Access

Once deployed, team members connect via:

```json
{
  "mcpServers": {
    "topmate-db": {
      "command": "/path/to/cloud-run-proxy.sh",
      "args": []
    }
  }
}
```

The `cloud-run-proxy.sh` script will authenticate via `gcloud auth print-identity-token` and connect to the Cloud Run service.

---

**Questions?** Check the logs first, then verify the Secret Manager secret and database user credentials.
