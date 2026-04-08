# Team MCP + Cloud SQL Read-Only Database Setup Guide

## Overview
This guide enables your entire team to query the read-only Cloud SQL database through Claude Desktop using the postgres-mcp server.

## What's Been Setup ✅

### Infrastructure (Already Configured)
- **Read-Only Database User**: `mcp_readonly`
- **Secret Manager Secret**: `postgres-mcp-readonly-uri`
- **Database**: Read-only replica (ds-dev-pg-replica, 35.200.225.202)
- **IAM Permissions**: Cloud Run service account granted Cloud SQL Client + Secret Manager Accessor roles

### Credentials
- **Database User**: `mcp_readonly`
- **Database**: `topmate_db_new`
- **Host**: Cloud SQL Unix socket (no IP whitelisting needed)
- **Connection Type**: Read-only with restricted SQL execution

## Option 1: Use Existing Cloud Run Service (Recommended Initially)

The easiest way to get started is using the existing postgres-mcp service that's already been set up. This allows your team to immediately start querying the read-only database.

### Step 1: Update Your Claude Desktop Config

**File Location**: `~/.config/claude/claude_desktop_config.json` (on Mac) or appropriate equivalent for your OS

**Add this configuration**:
```json
{
  "mcpServers": {
    "topmate-readonly-db": {
      "command": "/path/to/cloud-run-proxy.sh",
      "args": []
    }
  }
}
```

### Step 2: Get the Cloud Run Proxy Script

**File**: `cloud-run-proxy.sh` (in postgres-mcp repository)

**Update the URL in the script** to point to the deployed Cloud Run service:
```bash
CLOUD_RUN_URL="https://postgres-mcp-readonly-[PROJECT-ID].asia-south1.run.app/sse"
```

### Step 3: Authenticate with GCP

Run this command once per machine:
```bash
gcloud auth login
```

This authenticates your local machine with GCP. The `cloud-run-proxy.sh` script will automatically get fresh tokens for each connection.

### Step 4: Test Connection

```bash
# Test the proxy script
./cloud-run-proxy.sh

# You should see MCP tools available in Claude
```

## What Your Team Can Do

Once setup, your team members can:

✅ **Query the Database**: Execute SELECT statements against any table
✅ **Analyze Query Plans**: Use EXPLAIN to optimize queries
✅ **View Database Health**: Check index health, connection stats, replication lag
✅ **Generate SQL**: Get context-aware SQL generation from Claude
❌ **No Write Access**: INSERT, UPDATE, DELETE operations are blocked (read-only)
❌ **No Admin Operations**: CREATE, DROP, ALTER operations are blocked

## Example Usage in Claude

```
User: "How many users are in the system?"
Claude: <analyzes schema and runs query>
Result: 3,929 users in the user_user table

User: "Show me the top 10 tables by size"
Claude: <generates optimized query>
Result: [table size analysis]

User: "Why is this query slow? SELECT ... FROM ..."
Claude: <runs EXPLAIN plan and provides analysis>
Result: [optimization suggestions]
```

## Troubleshooting

### "Cannot connect to database"
1. Run `gcloud auth login` to refresh credentials
2. Check if cloud-run-proxy.sh script is executable: `chmod +x cloud-run-proxy.sh`
3. Verify the Cloud Run URL in the script is correct

### "Permission denied" errors
This likely means your team member needs `roles/run.invoker` IAM permission. Contact the admin.

### "Read-only violation" errors
This is expected - the database is read-only by design. Contact admin if you need write access for a specific task.

## Admin Tasks

### Granting Access to Team Members

For each team member, grant the `roles/run.invoker` role:

```bash
gcloud projects add-iam-policy-binding ds-dev-474406 \
  --member="user:team.member@company.com" \
  --role="roles/run.invoker" \
  --project=ds-dev-474406
```

### Monitoring Usage

View Cloud Run logs:
```bash
gcloud run services list --project=ds-dev-474406
gcloud logging read 'resource.type="cloud_run_revision"' --project=ds-dev-474406 --limit=50
```

### Revoking Access

```bash
gcloud projects remove-iam-policy-binding ds-dev-474406 \
  --member="user:team.member@company.com" \
  --role="roles/run.invoker" \
  --project=ds-dev-474406
```

## Security Notes

⚠️ **For Team Members:**
- **Don't share gcloud tokens** - each person must run `gcloud auth login` on their own machine
- **Don't commit cloud-run-proxy.sh changes with credentials** - the script only reads from environment
- Keep your machine's gcloud credentials secure

⚠️ **For Admins:**
- The read-only replica provides physical database-level protection against writes
- postgres-mcp `--access-mode=restricted` adds SQL-level protection
- All queries are logged in Cloud Run logs
- Monitor for unusual query patterns

## Architecture

```
Team Member's Claude Desktop
    ↓ (HTTPS + gcloud auth token)
Cloud Run postgres-mcp Service
    ↓ (Unix socket, no public IP)
Cloud SQL Read-Only Replica
    (ds-dev-pg-replica, 35.200.225.202)
```

**Benefits of This Setup:**
- ✅ No IP whitelisting needed - works from anywhere
- ✅ Scalable to unlimited team members
- ✅ IAM-based authentication - integrates with company SSO
- ✅ Encrypted connections (gRPC over HTTPS)
- ✅ Audit logging for all queries
- ✅ Cost-effective - Cloud Run scales to zero

## Support & Questions

For technical questions or issues:
1. Check the troubleshooting section above
2. Review Cloud Run logs: `gcloud logging read...`
3. Test connection directly: `psql -h 35.200.225.202 -U mcp_readonly -d topmate_db_new`

For access requests, contact: [Admin Email]

---

**Last Updated**: 2025-12-04
**Configuration Version**: 1.0
