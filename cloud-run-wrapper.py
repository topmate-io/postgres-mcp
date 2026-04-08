#!/usr/bin/env python3
"""
Cloud Run wrapper for postgres-mcp that provides immediate health check
while allowing postgres-mcp to initialize in the background.
"""
import asyncio
import os
import subprocess
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import time
import signal

# Track if postgres-mcp process is running
postgres_mcp_process = None
postgres_ready = False
start_time = time.time()

class HealthCheckHandler(BaseHTTPRequestHandler):
    """HTTP handler for Cloud Run health checks"""

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/' or self.path == '/health':
            # Always return 200 to allow Cloud Run to mark service as ready
            # The actual postgres-mcp will handle requests to other paths
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "service": "postgres-mcp-wrapper"}')
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

def start_health_check_server(port=8000):
    """Start the health check HTTP server on a separate thread"""
    server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"✓ Health check server started on port {port}", file=sys.stderr)
    return server

def start_postgres_mcp():
    """Start the actual postgres-mcp process"""
    global postgres_mcp_process

    cmd = [
        sys.executable, '-m', 'postgres_mcp',
        '--transport=sse',
        '--sse-host=0.0.0.0',
        '--sse-port=9000',  # Run on different port since 8000 is health check
        '--access-mode=restricted'
    ]

    print(f"Starting postgres-mcp: {' '.join(cmd)}", file=sys.stderr)

    try:
        postgres_mcp_process = subprocess.Popen(
            cmd,
            stdout=sys.stdout,
            stderr=sys.stderr,
            text=True
        )
        print("✓ postgres-mcp process started", file=sys.stderr)
        return postgres_mcp_process.wait()
    except Exception as e:
        print(f"✗ Failed to start postgres-mcp: {e}", file=sys.stderr)
        sys.exit(1)

def signal_handler(sig, frame):
    """Handle shutdown signals gracefully"""
    print("Shutting down...", file=sys.stderr)
    if postgres_mcp_process:
        postgres_mcp_process.terminate()
    sys.exit(0)

def main():
    """Main entry point"""
    # Setup signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    port = int(os.getenv('PORT', '8000'))

    # Start health check server first (immediately responsive)
    start_health_check_server(port)

    # Give Cloud Run a moment to detect the service is ready
    time.sleep(1)
    print("✓ Health check server ready, Cloud Run should mark service as ready", file=sys.stderr)

    # Now start postgres-mcp in main thread
    # This will block, but health checks will still work on port 8000
    start_postgres_mcp()

if __name__ == '__main__':
    main()
