#!/bin/bash
set -e

echo "=== postgres-mcp Cloud Run Startup ==="

# Cloud SQL instance in format: PROJECT:REGION:INSTANCE
CLOUD_SQL_INSTANCE="ds-dev-474406:asia-south1:ds-dev-pg"

echo "Starting Cloud SQL Proxy..."
echo "Cloud SQL Instance: $CLOUD_SQL_INSTANCE"

# Start cloud-sql-proxy in background
# This creates a TCP socket at 127.0.0.1:5432
/cloud-sql-proxy \
  "$CLOUD_SQL_INSTANCE" \
  --port=5432 \
  --ip=127.0.0.1 &

PROXY_PID=$!
echo "✓ Cloud SQL Proxy started with PID $PROXY_PID"

# Wait for proxy to be ready (give it time to establish connection)
echo "Waiting for Cloud SQL Proxy to be ready..."
sleep 10

# Build DATABASE_URI pointing to localhost:5432
# DATABASE_URI env var contains credentials: postgresql://user:pass@host/database
# We parse it and rebuild pointing to localhost
if [ -n "$DATABASE_URI" ]; then
  # Extract user, password, and database from existing URI
  DB_USER=$(echo "$DATABASE_URI" | sed -n 's/.*:\/\/\([^:]*\).*/\1/p')
  DB_PASS=$(echo "$DATABASE_URI" | sed -n 's/.*:\([^@]*\)@.*/\1/p')
  DB_NAME=$(echo "$DATABASE_URI" | sed -n 's/.*\/\([^?]*\).*/\1/p')

  # Create new URI pointing to localhost proxy
  export DATABASE_URI="postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}"
  echo "✓ DATABASE_URI configured to use Cloud SQL Proxy"
fi

echo "Starting postgres-mcp..."
echo "Listening on 0.0.0.0:8000"

# Start postgres-mcp in foreground
python -m postgres_mcp \
  --transport=sse \
  --sse-host=0.0.0.0 \
  --sse-port=8000 \
  --access-mode=restricted &

MCP_PID=$!
echo "✓ postgres-mcp started with PID $MCP_PID"

# Wait for both processes
wait $PROXY_PID $MCP_PID
