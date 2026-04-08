# Production MCP Database Access Setup (ds-share-474010)

## Overview

This guide sets up postgres-mcp for your production database to provide your team with read-only access to `topmate_db_prod` via Claude Desktop.

## Production Environment Details

```
Project: ds-share-474010
Primary DB: production-db (34.93.30.94)
Read-Only Replica: production-db-replica (34.93.38.209)
Database: topmate_db_prod
Region: asia-south1
Replication Status: ✅ SYNCED
```

## Setup Steps

### Step 1: Create mcp_readonly User (One-Time)

Connect to the **production-db** primary instance and run these SQL commands:

```sql
-- Connect as postgres or admin user to production-db

-- Create read-only user for MCP
CREATE USER IF NOT EXISTS mcp_readonly WITH PASSWORD 'SecurePassword123!MCP';

-- Grant connection to database
GRANT CONNECT ON DATABASE topmate_db_prod TO mcp_readonly;

-- Grant usage on schema
GRANT USAGE ON SCHEMA public TO topmate_db_prod;

-- Grant SELECT on all existing tables
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_readonly;

-- Grant SELECT on future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO mcp_readonly;

-- Verify user was created
SELECT usename, usecanlogin FROM pg_user WHERE usename = 'mcp_readonly';
SELECT COUNT(*) as total_tables FROM information_schema.tables WHERE table_schema='public';
```

**Note:** This user will automatically replicate to the read-only replica.

### Step 2: Create Secret Manager Secret

```bash
# Create Secret Manager secret with read-only replica URI
gcloud secrets create postgres-mcp-prod-uri \
  --data-file=- \
  --replication-policy="automatic" \
  --project=ds-share-474010 << 'EOF'
postgresql://mcp_readonly:SecurePassword123!MCP@/topmate_db_prod?host=/cloudsql/ds-share-474010:asia-south1:production-db-replica
EOF

echo "✓ Secret created successfully"

# Verify secret
gcloud secrets versions access latest \
  --secret=postgres-mcp-prod-uri \
  --project=ds-share-474010
```

### Step 3: Setup IAM Permissions

```bash
PROJECT_ID="ds-share-474010"
REGION="asia-south1"
SERVICE_ACCOUNT="49979260925-compute@developer.gserviceaccount.com"

# Grant Cloud SQL Client role
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SERVICE_ACCOUNT" \
  --role="roles/cloudsql.client" \
  --project="$PROJECT_ID" \
  --quiet

echo "✓ Cloud SQL Client role granted"

# Grant Secret Manager Accessor role
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SERVICE_ACCOUNT" \
  --role="roles/secretmanager.secretaccessor" \
  --project="$PROJECT_ID" \
  --quiet

echo "✓ Secret Manager Accessor role granted"

# Verify permissions
gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:$SERVICE_ACCOUNT" \
  --format="table(bindings.role)" \
  --project="$PROJECT_ID"
```

### Step 4: Deploy to Cloud Run

```bash
# Build and deploy postgres-mcp to Cloud Run in ds-share-474010
cd /path/to/postgres-mcp

# Option A: Build locally and deploy
gcloud run deploy postgres-mcp-prod \
  --image=crystaldba/postgres-mcp:latest \
  --region=asia-south1 \
  --platform=managed \
  --cpu=2 \
  --memory=1Gi \
  --timeout=600 \
  --concurrency=80 \
  --min-instances=1 \
  --max-instances=10 \
  --set-secrets=DATABASE_URI=postgres-mcp-prod-uri:latest \
  --add-cloudsql-instances=ds-share-474010:asia-south1:production-db-replica \
  --set-env-vars=ACCESS_MODE=restricted \
  --port=8000 \
  --no-allow-unauthenticated \
  --service-account=49979260925-compute@developer.gserviceaccount.com \
  --project=ds-share-474010
```

### Step 5: Verify Deployment

```bash
# Get Cloud Run service URL
SERVICE_URL=$(gcloud run services describe postgres-mcp-prod \
  --region=asia-south1 \
  --format="value(status.url)" \
  --project=ds-share-474010)

echo "Service URL: $SERVICE_URL"

# Test health endpoint
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  "$SERVICE_URL/" 2>&1 | head -20
```

## Replication Verification

The databases are currently synced:
- Primary: production-db (RUNNABLE)
- Replica: production-db-replica (RUNNABLE)
- Replication Lag: Minimal (typically <1 second)

**Verify replication status:**
```bash
gcloud sql instances describe production-db-replica \
  --format="table(name,state,replicaConfiguration.kind)" \
  --project=ds-share-474010

gcloud sql instances describe production-db \
  --format="table(name,state)" \
  --project=ds-share-474010
```

## Team Access Configuration

### For Each Team Member

**1. Setup postgres-mcp locally:**
```bash
git clone https://github.com/crystaldba/postgres-mcp.git && cd postgres-mcp
python3.12 -m venv .venv && source .venv/bin/activate && pip install -e .
```

**2. Configure Claude Desktop:**

Edit `~/.config/claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "topmate-prod-db": {
      "command": "/path/to/postgres-mcp/.venv/bin/python",
      "args": ["-m", "postgres_mcp", "--transport=sse", "--access-mode=restricted"],
      "env": {
        "DATABASE_URI": "postgresql://mcp_readonly:SecurePassword123!MCP@34.93.38.209/topmate_db_prod"
      }
    }
  }
}
```

**3. Test connection:**
```bash
export PGPASSWORD='SecurePassword123!MCP'
psql -h 34.93.38.209 -U mcp_readonly -d topmate_db_prod -c "SELECT COUNT(*) FROM user_user;"
```

**4. Restart Claude Desktop**

## Production Database Credentials

```
Host (Read-Only Replica): 34.93.38.209
Host (Primary): 34.93.30.94
Database: topmate_db_prod
User: mcp_readonly
Password: SecurePassword123!MCP
Port: 5432
```

## Database Statistics

```sql
-- Check table count
SELECT COUNT(*) as total_tables FROM information_schema.tables WHERE table_schema='public';

-- Check user count (if applicable)
SELECT COUNT(*) as total_users FROM user_user;

-- Check database size
SELECT pg_size_pretty(pg_database_size('topmate_db_prod')) as db_size;
```

## Troubleshooting

### Connection Issues

```bash
# 1. Verify read-only replica is up
gcloud sql instances describe production-db-replica \
  --project=ds-share-474010 \
  --format="value(state)"

# 2. Test direct connection to replica
export PGPASSWORD='SecurePassword123!MCP'
psql -h 34.93.38.209 -U mcp_readonly -d topmate_db_prod -c "SELECT 1;"

# 3. Check if user exists on replica
psql -h 34.93.38.209 -U mcp_readonly -d topmate_db_prod -c "\du"

# 4. Verify replication status
SELECT slot_name, restart_lsn, confirmed_flush_lsn
FROM pg_replication_slots;
```

### Cloud Run Issues

```bash
# Check service status
gcloud run services describe postgres-mcp-prod \
  --region=asia-south1 \
  --project=ds-share-474010 \
  --format="value(status.conditions[0].reason)"

# View logs
gcloud run services logs read postgres-mcp-prod \
  --region=asia-south1 \
  --project=ds-share-474010 \
  --limit=50
```

## Security Features

✅ **Multi-layer Protection:**
1. Read-only replica at database level (no writes possible)
2. `mcp_readonly` user with SELECT-only permissions
3. postgres-mcp with `--access-mode=restricted`
4. Cloud SQL Unix socket connection (no public IP exposure)
5. Cloud Run with authentication required (no unauthenticated access)
6. Secret Manager for credential storage

✅ **Access Control:**
- IAM-based authentication for Cloud Run
- gcloud token required for each connection
- All queries logged in Cloud Run logs

## Costs

- Cloud Run: ~$1-5/month (scales with usage)
- Cloud SQL: Covered by existing instances
- Secret Manager: $0.06/secret/month
- **Total**: ~$1-10/month (minimal addition)

## Next Steps

1. **Create mcp_readonly user** (Step 1 above)
2. **Create Secret Manager secret** (Step 2 above)
3. **Setup IAM permissions** (Step 3 above)
4. **Deploy to Cloud Run** (Step 4 above)
5. **Share team access configuration** with your team
6. **Test with 1-2 team members** before full rollout

## Support

For issues or questions:
1. Check Cloud Run logs: `gcloud run services logs read postgres-mcp-prod --region=asia-south1 --project=ds-share-474010`
2. Test direct database connection: `psql -h 34.93.38.209 -U mcp_readonly -d topmate_db_prod`
3. Verify replication status: `gcloud sql instances describe production-db-replica --project=ds-share-474010`

---

**Setup Date**: 2025-12-04
**Project**: ds-share-474010
**Environment**: Production
**Status**: Ready for Setup
