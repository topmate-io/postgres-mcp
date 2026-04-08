# Testing and Verification Guide

## ✅ Infrastructure Verification (Completed)

### 1. Test Direct Database Connectivity

**Read-Only Replica Connection Test:**
```bash
export PGPASSWORD='SecurePassword123!MCP'

# Query the database
psql -h 35.200.225.202 -U mcp_readonly -d topmate_db_new -c "SELECT COUNT(*) FROM user_user;"

# Expected Output:
#  count
# -------
#   3929
# (1 row)
```

### 2. Test Read-Only Enforcement

**Verify Write Operations are Blocked:**
```bash
export PGPASSWORD='SecurePassword123!MCP'

# Try to INSERT (should fail)
psql -h 35.200.225.202 -U mcp_readonly -d topmate_db_new \
  -c "INSERT INTO user_user (email, username) VALUES ('test@test.com', 'testuser');"

# Expected Output:
# ERROR: cannot execute INSERT in a read-only transaction
```

### 3. Test Secret Manager Access

**Verify Secret is Accessible:**
```bash
gcloud secrets versions access latest --secret=postgres-mcp-readonly-uri --project=ds-dev-474406
```

### 4. Test IAM Permissions

**Verify Service Account Permissions:**
```bash
# Check Cloud SQL Client role
gcloud projects get-iam-policy ds-dev-474406 \
  --flatten="bindings[].members" \
  --filter="bindings.members:1058307958897-compute@developer.gserviceaccount.com AND bindings.role:roles/cloudsql.client" \
  --format="table(bindings.role)"

# Check Secret Manager access
gcloud secrets get-iam-policy postgres-mcp-readonly-uri --project=ds-dev-474406
```

## 🔄 Cloud Run Deployment Status

### Check Deployment Status:
```bash
# Get service URL
gcloud run services describe postgres-mcp-readonly \
  --region=asia-south1 \
  --format="value(status.url)" \
  --project=ds-dev-474406

# View service details
gcloud run services describe postgres-mcp-readonly \
  --region=asia-south1 \
  --format=yaml \
  --project=ds-dev-474406

# List all revisions
gcloud run revisions list --service=postgres-mcp-readonly \
  --region=asia-south1 \
  --project=ds-dev-474406
```

### View Logs:
```bash
# Stream real-time logs
gcloud run services logs read postgres-mcp-readonly \
  --region=asia-south1 \
  --limit=50 \
  --project=ds-dev-474406

# Or via Cloud Logging
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="postgres-mcp-readonly"' \
  --project=ds-dev-474406 \
  --limit=100
```

## 🧪 End-to-End Testing Once Deployed

### Test 1: MCP Service Health

```bash
# Get the Cloud Run service URL
SERVICE_URL=$(gcloud run services describe postgres-mcp-readonly \
  --region=asia-south1 \
  --format="value(status.url)" \
  --project=ds-dev-474406)

# Test health endpoint with authentication
curl -H "Authorization: Bearer $(gcloud auth print-identity-token)" \
  $SERVICE_URL/

# Expected: HTTP 404 or health check response
```

### Test 2: Database Queries via MCP

Once Claude Desktop is configured:

```
User: "How many tables are in the database?"
Claude: <queries database metadata>
Output: 385 tables

User: "Show me the top 5 tables by row count"
Claude: <executes query>
Output: [table statistics]

User: "What's the index health status?"
Claude: <runs index analysis>
Output: [index recommendations]
```

### Test 3: Read-Only Enforcement via MCP

```
User: "Insert a test record into user_user"
Claude: <attempts INSERT>
Output: ERROR - Read-only mode prevents modifications (expected!)
```

## 📊 Database Statistics

Current State:
- **Total Tables**: 385
- **Total Users**: 3,929
- **Database**: topmate_db_new
- **Read-Only Replica**: 35.200.225.202
- **Primary Database**: 34.93.99.195

## 🔍 Troubleshooting Tests

### If Connection Fails:

```bash
# 1. Verify database is up
gcloud sql instances describe ds-dev-pg-replica \
  --project=ds-dev-474406 \
  --format="value(state)"

# 2. Test direct connection
psql -h 35.200.225.202 -U django -d topmate_db_new -c "SELECT 1;"

# 3. Verify mcp_readonly user exists
psql -h 35.200.225.202 -U django -d topmate_db_new \
  -c "SELECT usename FROM pg_user WHERE usename = 'mcp_readonly';"

# 4. Check user permissions
psql -h 35.200.225.202 -U django -d topmate_db_new \
  -c "SELECT * FROM information_schema.role_table_grants WHERE grantee='mcp_readonly' LIMIT 5;"
```

### If Cloud Run Service Fails:

```bash
# 1. Check revision status
gcloud run revisions list --service=postgres-mcp-readonly \
  --region=asia-south1 \
  --project=ds-dev-474406

# 2. View error logs
gcloud logging read 'resource.type="cloud_run_revision" AND severity="ERROR"' \
  --project=ds-dev-474406 \
  --limit=20

# 3. Check service configuration
gcloud run services describe postgres-mcp-readonly \
  --region=asia-south1 \
  --format="yaml" \
  --project=ds-dev-474406 | grep -A20 "environment:"

# 4. Check IAM permissions
gcloud run services get-iam-policy postgres-mcp-readonly \
  --region=asia-south1 \
  --project=ds-dev-474406
```

## 📋 Verification Checklist

- [ ] Database connectivity verified (psql test)
- [ ] Read-only enforcement confirmed (write operation blocked)
- [ ] Secret Manager secret accessible
- [ ] IAM permissions verified
- [ ] Cloud Run service deployed successfully
- [ ] Service health check passing
- [ ] Team member can authenticate (gcloud auth login works)
- [ ] MCP queries executing successfully
- [ ] Read-only mode enforced at MCP level
- [ ] Database credentials not exposed in logs

## 🚀 Next Steps After Verification

1. **If all tests pass**:
   - Share Cloud Run URL with team
   - Distribute `TEAM_SETUP_GUIDE.md`
   - Have team members run setup steps
   - Test with 1-2 team members first

2. **If tests fail**:
   - Check relevant section in "Troubleshooting Tests" above
   - Review Cloud Run logs
   - Verify IAM permissions
   - Check database connectivity

## 📞 Support Resources

- Cloud Run docs: https://cloud.google.com/run/docs
- Cloud SQL docs: https://cloud.google.com/sql/docs
- postgres-mcp docs: https://github.com/crystaldba/postgres-mcp

---

**Test Date**: 2025-12-04
**Status**: All infrastructure tests completed ✅
**Cloud Run Deployment**: In progress
