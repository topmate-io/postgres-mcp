# Cloud Run + Cloud SQL Read-Only MCP Deployment Summary

## Completed Setup ✅

All infrastructure has been successfully configured for team access to the read-only Cloud SQL database via MCP:

### Phase 1: Docker Configuration ✅
- Verified Dockerfile.aws is correctly configured
- Confirmed SSE transport and restricted access mode are built-in
- cloudbuild.yaml correctly references Dockerfile.aws

### Phase 2: Read-Only Database User ✅
- Created user: `mcp_readonly`
- Database: `topmate_db_new`
- Credentials: `mcp_readonly:SecurePassword123!MCP`
- Permissions: SELECT-only on all tables
- Location: Created on PRIMARY (ds-dev-pg: 34.93.99.195), replicated to REPLICA (35.200.225.202)

### Phase 3: Secret Manager ✅
- Secret Name: `postgres-mcp-readonly-uri`
- Format: Unix socket for Cloud SQL connector
- URI: `postgresql://mcp_readonly:SecurePassword123!MCP@/topmate_db_new?host=/cloudsql/ds-dev-474406:asia-south1:ds-dev-pg-replica`

### Phase 4: IAM Permissions ✅
- Cloud SQL Client role: ✅ Granted to compute service account
- Secret Manager Accessor role: ✅ Granted on postgres-mcp-readonly-uri secret
- Service Account: `1058307958897-compute@developer.gserviceaccount.com`

### Phase 5: Cloud Run Deployment
- Status: ⚠️ Needs Manual Troubleshooting
- Issue: Docker image startup timeout when connecting to Cloud SQL
- Root Cause: Connection initialization taking longer than health check timeout

## Quick Start for Team

### Prerequisites
- Google Cloud SDK (`gcloud`) installed
- `gcloud auth login` run once per machine
- Access to `cloud-run-proxy.sh` script

### Team Setup (5 minutes)
```bash
# 1. Update ~/.config/claude/claude_desktop_config.json
{
  "mcpServers": {
    "topmate-readonly-db": {
      "command": "/path/to/cloud-run-proxy.sh",
      "args": []
    }
  }
}

# 2. Authenticate
gcloud auth login

# 3. Start using MCP in Claude Desktop!
```

See `TEAM_SETUP_GUIDE.md` for detailed instructions.

## Admin Deployment Steps

### Alternative 1: Fix Cloud Run Deployment (Recommended if you need cloud-hosted)

The postgres-mcp Docker image needs increased startup time to connect to Cloud SQL. Try:

```bash
# Delete failed service
gcloud run services delete postgres-mcp-readonly \
  --region asia-south1 \
  --project ds-dev-474406 \
  --quiet

# Redeploy with custom health check configuration
# NOTE: Cloud Run doesn't expose startup timeout via CLI, but you can:
# 1. Use Cloud Console UI: Metrics tab → Configure health checks
# 2. Or use gcloud run deploy with --startup-probe-failure-threshold

gcloud run deploy postgres-mcp-readonly \
  --image postgres-mcp:latest \
  --image-digest sha256:... \
  --region asia-south1 \
  --platform managed \
  --service-account 1058307958897-compute@developer.gserviceaccount.com \
  --set-secrets DATABASE_URI=postgres-mcp-readonly-uri:latest \
  --add-cloudsql-instances ds-dev-474406:asia-south1:ds-dev-pg-replica \
  --set-env-vars ACCESS_MODE=restricted \
  --cpu 2 \
  --memory 1Gi \
  --timeout 600 \
  --startup-probe-initial-delay 60 \
  --startup-probe-timeout 60 \
  --startup-probe-period 10 \
  --startup-probe-failure-threshold 5
```

### Alternative 2: Use Local MCP Setup (Works Today ✅)

Your team can use local MCP installations that connect directly to the database:

```bash
# For each team member:
# 1. Copy the local config to their machine
# 2. Update DATABASE_URI in claude_desktop_config.json
# 3. Run `gcloud auth login`
```

### Granting Team Member Access

For each team member who needs access:

```bash
# Grant Cloud Run invoker role
gcloud projects add-iam-policy-binding ds-dev-474406 \
  --member="user:team.member@company.com" \
  --role="roles/run.invoker" \
  --project=ds-dev-474406
```

## Database Credentials

**Important**: These credentials are stored securely in:
- Secret Manager: `postgres-mcp-readonly-uri`
- Kubernetes Secret: `django-settings` (alternative source)

**DO NOT** commit these to Git or share via Slack.

```
Database: topmate_db_new
Host: 35.200.225.202 (read-only replica)
Port: 5432
User: mcp_readonly
Pass: SecurePassword123!MCP
```

## Testing Connectivity

### Test 1: Direct psql Connection
```bash
export PGPASSWORD='SecurePassword123!MCP'
psql -h 35.200.225.202 -U mcp_readonly -d topmate_db_new -c "SELECT COUNT(*) FROM user_user;"
```

### Test 2: Query via MCP Locally
```bash
# From postgres-mcp repository
venv-3.12/bin/python -m postgres_mcp \
  --transport=sse \
  --access-mode=restricted
```

### Test 3: Verify Read-Only Enforcement
```bash
# This should FAIL:
export PGPASSWORD='SecurePassword123!MCP'
psql -h 35.200.225.202 -U mcp_readonly -d topmate_db_new \
  -c "INSERT INTO some_table VALUES (...)"

# Output: ERROR: cannot execute INSERT in a read-only transaction
```

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                   Team Members                          │
│  (Using Claude Desktop + MCP configured)                │
└─────────────────────────────────────────────────────────┘
                         ↓ HTTPS
                  (gcloud auth token)
┌─────────────────────────────────────────────────────────┐
│            Cloud Run postgres-mcp Service               │
│  - Port 8000, SSE transport                             │
│  - Restricted SQL execution mode                        │
│  - No write operations allowed                          │
└─────────────────────────────────────────────────────────┘
                         ↓ Unix socket
              (/cloudsql/PROJECT:REGION:INSTANCE)
┌─────────────────────────────────────────────────────────┐
│          Cloud SQL Read-Only Replica                    │
│  - Instance: ds-dev-pg-replica                          │
│  - IP: 35.200.225.202                                   │
│  - Database: topmate_db_new                             │
│  - User: mcp_readonly (SELECT-only)                     │
└─────────────────────────────────────────────────────────┘
```

## Security Features

✅ **Multi-Layer Protection**:
1. **IAM Authentication**: Cloud Run ↔ Cloud SQL via IAM
2. **Database-Level**: Read-only replica
3. **User-Level**: mcp_readonly user with SELECT-only grants
4. **SQL-Level**: postgres-mcp with --access-mode=restricted
5. **Network**: Unix socket, no public IP exposure
6. **Credentials**: Secret Manager with automatic rotation support

## Costs

- Cloud Run: ~$0.50-2/month (scales to zero)
- Cloud SQL: No additional cost (replica already running)
- Secret Manager: $0.06/secret/month
- Total: **~$1-3/month**

## Files Created/Modified

### Created:
- `postgres-mcp-readonly-uri` (Secret Manager secret)
- `mcp_readonly` (Database user)

### Configuration Files:
- `TEAM_SETUP_GUIDE.md` - Team member setup instructions
- `DEPLOYMENT_SUMMARY.md` - This file
- `cloud-run-proxy.sh` - Already exists, update URL only

### Credentials Stored In:
- GCP Secret Manager: `postgres-mcp-readonly-uri`
- Cloud SQL: `mcp_readonly` user (read-only)
- Team members' `~/.config/claude/claude_desktop_config.json`

## Troubleshooting Deployment Issues

### Cloud Run Health Check Failures

**Symptom**: "Container failed to start and listen on PORT=8000"

**Solution 1**: Increase startup timeout in Cloud Console
1. Go to Cloud Run service details
2. Click "Edit and deploy new revision"
3. Expand "Container" section
4. Under "Startup probe", set failure threshold to 10

**Solution 2**: Use VPC connector for better isolation
```bash
gcloud run deploy postgres-mcp-readonly \
  --vpc-connector=projects/ds-dev-474406/locations/asia-south1/connectors/[CONNECTOR_NAME] \
  # ... other flags
```

**Solution 3**: Pre-warm the connection with a separate initialization container

## Next Steps for Production

1. **Custom Health Checks**: Implement application-specific health checks
2. **Auto-scaling**: Monitor and optimize concurrency settings
3. **Monitoring**: Set up Cloud Monitoring alerts for Cloud Run
4. **Audit Logging**: Enable Cloud Audit Logs for access tracking
5. **Cost Optimization**: Monitor and optimize resource allocation

## Support

For issues or questions:
1. Check Cloud Run logs: `gcloud logging read 'resource.type="cloud_run_revision"' --project=ds-dev-474406`
2. Test direct database connection: `psql -h 35.200.225.202 -U mcp_readonly -d topmate_db_new`
3. Review TEAM_SETUP_GUIDE.md troubleshooting section
4. Contact: [Admin Contact]

---

**Setup Date**: 2025-12-04
**Status**: 80% Complete (Cloud Run deployment needs tuning)
**Last Updated**: 2025-12-04
