#!/bin/bash
# Cloud Run entrypoint with Cloud SQL Proxy v2

# Redirect all output (stdout and stderr) to stderr so it appears in Cloud Run logs
exec 2>&1

echo "=========================================="
echo "postgres-mcp Cloud Run Startup"
echo "=========================================="
echo ""

# Cloud SQL instance in format: PROJECT:REGION:INSTANCE
# Note: This is for Cloud SQL proxy; we're using direct PostgreSQL connection instead
CLOUD_SQL_INSTANCE="ds-share-474010:asia-south1:ds-share-pg"

echo "Step 1: Starting Cloud SQL Proxy v2..."
echo "Instance: $CLOUD_SQL_INSTANCE"
echo "Proxy binary: /cloud-sql-proxy"
echo "Proxy version info:"
/cloud-sql-proxy --version 2>&1 || echo "  (version check failed)"
echo ""

# Start cloud-sql-proxy v2 in background
# Uses Application Default Credentials from service account
# v2 syntax: proxy [instance-connection-string] --port=PORT --address=ADDR
echo "Starting: /cloud-sql-proxy $CLOUD_SQL_INSTANCE --port=5432 --address=127.0.0.1"
/cloud-sql-proxy \
  "$CLOUD_SQL_INSTANCE" \
  --port=5432 \
  --address=127.0.0.1 > /tmp/proxy.log 2>&1 &

PROXY_PID=$!
echo "✓ Cloud SQL Proxy started (PID: $PROXY_PID)"
echo ""

# Give proxy time to initialize
echo "Waiting 15 seconds for proxy to be ready..."
sleep 15

# Check if proxy is running
if ps -p $PROXY_PID > /dev/null 2>&1; then
  echo "✓ Cloud SQL Proxy is still running"
  echo "Proxy logs:"
  head -20 /tmp/proxy.log 2>/dev/null || echo "  (no logs available)"
else
  echo "✗ Cloud SQL Proxy died! Last logs:"
  tail -20 /tmp/proxy.log 2>/dev/null || echo "  (no logs available)"
  sleep 2
fi

echo ""
echo "Step 2: Configuring DATABASE_URI..."
# The DATABASE_URI from secret points to localhost:5432 (which proxy listens on)
if [ -n "$DATABASE_URI" ]; then
  echo "DATABASE_URI is set (length: ${#DATABASE_URI})"
  echo "First 70 chars: ${DATABASE_URI:0:70}"
else
  echo "WARNING: DATABASE_URI environment variable not set!"
fi

echo ""
echo "Step 3: Starting postgres-mcp server..."
echo "Listening on 0.0.0.0:8000"
echo ""

# Start postgres-mcp - this should now connect via the proxy on localhost:5432
exec python -m postgres_mcp \
  --transport=sse \
  --sse-host=0.0.0.0 \
  --sse-port=8000 \
  --access-mode=restricted
