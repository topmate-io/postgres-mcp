#!/bin/bash
# Proxy script for authenticated Cloud Run MCP access
# This script refreshes the gcloud identity token and passes it to mcp-remote

CLOUD_RUN_URL="https://postgres-mcp-49979260925.asia-south1.run.app/sse"

# Get fresh identity token
TOKEN=$(gcloud auth print-identity-token 2>/dev/null)

if [ -z "$TOKEN" ]; then
    echo "Error: Could not get gcloud identity token. Run 'gcloud auth login' first." >&2
    exit 1
fi

# Run mcp-remote with the auth header
exec npx -y mcp-remote "$CLOUD_RUN_URL" --header "Authorization: Bearer $TOKEN"
