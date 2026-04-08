# Team Access to Read-Only Cloud SQL Database ✅

## Status Summary

All infrastructure is successfully configured:
- ✅ Read-only database user created: `mcp_readonly`
- ✅ Secret Manager secret created: `postgres-mcp-readonly-uri`
- ✅ IAM permissions configured (Cloud SQL Client + Secret Manager Accessor)
- ✅ Database connectivity verified
- ✅ Read-only enforcement confirmed

## Quick Start for Team (Option A: Local MCP)

### Step 1: Install postgres-mcp locally

```bash
# Clone if not already cloned
git clone https://github.com/crystaldba/postgres-mcp.git
cd postgres-mcp

# Set up Python environment
python3.12 -m venv .venv
source .venv/bin/activate

# Install postgres-mcp
pip install -e .
```

### Step 2: Configure Claude Desktop

Edit `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "topmate-readonly-db": {
      "command": "/path/to/postgres-mcp/.venv/bin/python",
      "args": [
        "-m",
        "postgres_mcp",
        "--transport=sse",
        "--access-mode=restricted"
      ],
      "env": {
        "DATABASE_URI": "postgresql://mcp_readonly:SecurePassword123!MCP@35.200.225.202/topmate_db_new"
      }
    }
  }
}
```

### Step 3: Test Connection

```bash
# Test direct database connection
export PGPASSWORD='SecurePassword123!MCP'
psql -h 35.200.225.202 -U mcp_readonly -d topmate_db_new -c "SELECT COUNT(*) FROM user_user;"

# Expected output: 3929 users
```

### Step 4: Restart Claude Desktop

Close and reopen Claude Desktop. You should see the MCP server active.

## Database Credentials

```
Host: 35.200.225.202 (read-only replica)
Database: topmate_db_new
User: mcp_readonly
Password: SecurePassword123!MCP
Port: 5432
```

## What You Can Do

✅ **SELECT queries** - Query any table
✅ **EXPLAIN queries** - Analyze query performance
✅ **Schema inspection** - View table structures
✅ **Analytics** - Generate reports from the database

❌ **INSERT/UPDATE/DELETE** - Blocked (read-only)
❌ **CREATE/DROP/ALTER** - Blocked (admin operations)

## Example Usage in Claude

```
User: "How many total users are in the system?"
Claude: <runs query>
Output: 3,929 users in the user_user table

User: "Show me the top 5 tables by size"
Claude: <generates and executes query>
Output: [table analysis]

User: "Explain why this query is slow: SELECT ... FROM ..."
Claude: <runs EXPLAIN plan>
Output: [optimization recommendations]
```

## Troubleshooting

### "Cannot connect to mcp_readonly user"
```bash
# Verify user exists and is accessible
export PGPASSWORD='SecurePassword123!MCP'
psql -h 35.200.225.202 -U mcp_readonly -d topmate_db_new -c "\du"
```

### "MCP server not appearing in Claude"
1. Verify DATABASE_URI is set correctly in claude_desktop_config.json
2. Restart Claude Desktop completely
3. Check that `.venv/bin/python -m postgres_mcp` runs without errors

### "Permission denied for schema public"
This indicates the user permissions weren't replicated. Contact admin.

## Security Notes

- **Don't share the password** - Each team member should have direct psql access
- **Don't expose credentials in Git** - claude_desktop_config.json should be local only
- **All queries are read-only** - No data modifications possible
- **Use mcp_readonly user** - Always, never use root/admin credentials

## Support

For access issues or questions:
1. Run the test connection command above
2. Verify your claude_desktop_config.json matches the template
3. Check Cloud SQL replica status: `gcloud sql instances describe ds-dev-pg-replica --project=ds-dev-474406`

---

**Setup Date**: 2025-12-04
**Database**: topmate_db_new (read-only replica)
**Connection Type**: Direct TCP (35.200.225.202)

