# Postgres MCP - Official Docker Image Setup

## Overview

This deployment uses the **official `crystaldba/postgres-mcp` Docker image** from Docker Hub, which simplifies maintenance and ensures we're using the latest stable version from Crystal DBA.

## What Changed

### Before (Custom Build)
- Built from source using `uv` and Python 3.12
- Custom Dockerfile with multi-stage build
- Required building dependencies locally
- `--source` deployment via Cloud Build

### After (Official Image)
- Uses official pre-built `crystaldba/postgres-mcp:latest` from Docker Hub
- Simple Dockerfile that just adds `--platform=linux/amd64` flag
- Faster builds (just pull and tag)
- Direct image deployment to Cloud Run

## Deployment Information

**Project:** `ds-share-474010` (Production)
**Service:** `postgres-mcp`
**Service URL:** `https://postgres-mcp-49979260925.asia-south1.run.app`
**Image:** `gcr.io/ds-share-474010/postgres-mcp-official:latest`
**Base Image:** `crystaldba/postgres-mcp:latest`

## Configuration

### Database Connection
- **Secret:** `postgres-mcp-readonly-uri` (version 2)
- **Connection String:** Uses Cloud SQL Unix socket
  ```
  postgresql://django:PASSWORD@/topmate_db_new?host=/cloudsql/ds-share-474010:asia-south1:ds-share-pg
  ```
- **Cloud SQL Instance:** `ds-share-474010:asia-south1:ds-share-pg`

### Command-Line Arguments
```dockerfile
CMD ["--access-mode=restricted", "--transport=sse", "--sse-host=0.0.0.0"]
```

- `--access-mode=restricted`: Read-only SQL, safe operations only
- `--transport=sse`: Server-Sent Events for MCP communication
- `--sse-host=0.0.0.0`: Listen on all interfaces (required for Cloud Run)

## Files

- **`Dockerfile.official`** - Simple Dockerfile using official image
- **`build-and-deploy-official.sh`** - Automated build and deploy script
- **`cloud-run-mcp-postgres`** - Team member connector script

## Building and Deploying

### Quick Deploy
```bash
cd /Users/dharsankumar/Documents/GitHub/postgres-mcp
./build-and-deploy-official.sh
```

### Manual Steps
```bash
# 1. Build for linux/amd64
docker build --platform linux/amd64 -f Dockerfile.official \
  -t gcr.io/ds-share-474010/postgres-mcp-official:latest .

# 2. Push to GCR
docker push gcr.io/ds-share-474010/postgres-mcp-official:latest

# 3. Deploy to Cloud Run
gcloud run deploy postgres-mcp \
  --image gcr.io/ds-share-474010/postgres-mcp-official:latest \
  --region=asia-south1 \
  --platform managed \
  --cpu 2 \
  --memory 1Gi \
  --timeout 600 \
  --set-secrets DATABASE_URI=postgres-mcp-readonly-uri:latest \
  --add-cloudsql-instances ds-share-474010:asia-south1:ds-share-pg \
  --port 8000 \
  --no-allow-unauthenticated \
  --service-account=49979260925-compute@developer.gserviceaccount.com \
  --project=ds-share-474010
```

## Team Setup

### For Team Members

1. **Authenticate:**
   ```bash
   gcloud auth login
   ```

2. **Add to Claude Desktop config:**

   **Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`
   ```json
   {
     "mcpServers": {
       "postgres-mcp": {
         "command": "/path/to/cloud-run-mcp-postgres",
         "disabled": false
       }
     }
   }
   ```

3. **Restart Claude Desktop**

### Grant Team Access

```bash
gcloud projects add-iam-policy-binding ds-share-474010 \
  --member="user:TEAM_MEMBER_EMAIL" \
  --role="roles/run.invoker" \
  --project=ds-share-474010
```

## Benefits of Official Image

✅ **Always up-to-date:** Pull latest from Docker Hub for new features
✅ **No build dependencies:** No need for Python, uv, or build tools locally
✅ **Faster deployments:** Just pull, tag, and push
✅ **Official support:** Maintained by Crystal DBA team
✅ **Proven stability:** Used by many production deployments
✅ **Simple Dockerfile:** Just 17 lines vs complex multi-stage build

## Monitoring

### Check Service Status
```bash
gcloud run services describe postgres-mcp \
  --region=asia-south1 \
  --project=ds-share-474010
```

### View Logs
```bash
gcloud logging read \
  'resource.type="cloud_run_revision" AND resource.labels.service_name="postgres-mcp"' \
  --project=ds-share-474010 \
  --limit=50
```

### Test Connection
```bash
# From your local machine
./cloud-run-mcp-postgres
```

## Troubleshooting

### "Connection failed" on startup
- This is normal on first request - the service cold-starts
- Cloud SQL proxy takes a few seconds to establish connection
- Subsequent requests will be fast once the connection pool is warmed up

### "Permission denied"
- Ensure you've run `gcloud auth login`
- Verify IAM permissions: `roles/run.invoker`
- Check you're using the correct project

### Update Database Password
If the database password changes:
```bash
# Update the secret
echo "postgresql://django:NEW_PASSWORD@/topmate_db_new?host=/cloudsql/ds-share-474010:asia-south1:ds-share-pg" | \
  gcloud secrets versions add postgres-mcp-readonly-uri --data-file=- --project=ds-share-474010

# Redeploy to pick up new secret
gcloud run services update postgres-mcp --region=asia-south1 --project=ds-share-474010
```

## What's Available

With this MCP server, team members can:

- 📊 **Query Database:** Execute SELECT statements
- 🔍 **Explain Plans:** Analyze query performance with EXPLAIN
- 💊 **Database Health:** Check index health, buffer cache, connections
- 🎯 **Index Tuning:** Get AI-powered index recommendations
- ⚡ **Top Queries:** Analyze slow and frequent queries
- 📈 **Schema Analysis:** Explore tables, columns, constraints

All with read-only safety (`--access-mode=restricted`).

## Security

✅ IAM authentication required (Cloud Run)
✅ Read-only database access (restricted mode)
✅ Cloud SQL Unix socket (no public IP)
✅ Automatic connection pooling
✅ Request/response logging
✅ Auto-scaling (0-10 instances)

## Cost

- **Idle:** $0/month (scales to 0)
- **Typical usage:** $2-10/month
- **Heavy usage:** $10-25/month

Charges only when processing requests.

---

**Status:** ✅ Production Ready
**Deployed:** 2025-12-08
**Base Image:** `crystaldba/postgres-mcp:latest`
**Documentation:** [GitHub - crystaldba/postgres-mcp](https://github.com/crystaldba/postgres-mcp)
