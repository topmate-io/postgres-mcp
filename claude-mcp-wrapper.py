#!/usr/bin/env python3
"""
MCP Stdio to HTTP/SSE Bridge
Allows Claude Desktop to communicate with remote MCP servers via HTTP/SSE
Uses subprocess curl for both SSE streaming and message posting
"""

import sys
import json
import subprocess
import threading
import queue
import time
import uuid

def get_auth_token() -> str:
    """Get gcloud identity token"""
    try:
        token = subprocess.check_output(
            ["gcloud", "auth", "print-identity-token"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        if not token:
            raise RuntimeError("Empty token")
        return token
    except Exception as e:
        print(f"Error: Unable to authenticate with gcloud: {e}", file=sys.stderr)
        print("Run: gcloud auth application-default login", file=sys.stderr)
        sys.exit(1)

def sse_reader_thread(token: str, base_url: str, session_id: str, output_queue: queue.Queue):
    """Read from SSE endpoint using curl"""
    curl_cmd = [
        "curl", "-s", "-N", "--no-buffer",
        "-H", f"Authorization: Bearer {token}",
        f"{base_url}/sse?session_id={session_id}"
    ]

    try:
        process = subprocess.Popen(
            curl_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )

        current_event = None
        for line in iter(process.stdout.readline, ''):
            line = line.rstrip('\n')
            if not line:
                continue

            if line.startswith('event: '):
                current_event = line[7:].strip()
            elif line.startswith('data: '):
                data = line[6:].strip()
                if data and current_event != 'endpoint':
                    try:
                        json.loads(data)  # Validate JSON
                        output_queue.put(data)
                    except json.JSONDecodeError:
                        pass

        process.wait()
    except Exception as e:
        print(f"SSE reader error: {e}", file=sys.stderr)

def send_message_to_server(token: str, base_url: str, session_id: str, message: dict):
    """Send a message to the server using curl"""
    try:
        curl_cmd = [
            "curl", "-s", "-L",  # -L follows redirects
            "-X", "POST",
            "-H", f"Authorization: Bearer {token}",
            "-H", "Content-Type: application/json",
            "-d", json.dumps(message),
            f"{base_url}/messages?session_id={session_id}"
        ]

        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            print(f"Message send failed: {result.stderr}", file=sys.stderr)
    except Exception as e:
        print(f"Error sending message: {e}", file=sys.stderr)

def main():
    """Main entry point"""
    token = get_auth_token()
    base_url = "https://postgres-mcp-49979260925.asia-south1.run.app"
    session_id = str(uuid.uuid4())

    output_queue = queue.Queue()

    # Start SSE reader thread
    reader = threading.Thread(
        target=sse_reader_thread,
        args=(token, base_url, session_id, output_queue),
        daemon=False
    )
    reader.start()

    # Give SSE connection time to establish
    time.sleep(0.2)

    try:
        while True:
            # Check for output from SSE reader (non-blocking)
            try:
                message = output_queue.get_nowait()
                sys.stdout.write(message + '\n')
                sys.stdout.flush()
            except queue.Empty:
                pass

            # Small sleep to avoid busy waiting
            time.sleep(0.01)

            # Try to read from stdin
            try:
                line = sys.stdin.readline()
                if not line:
                    # stdin closed
                    break
                line = line.strip()
                if line:
                    try:
                        message_obj = json.loads(line)
                        send_message_to_server(token, base_url, session_id, message_obj)
                    except json.JSONDecodeError:
                        print(f"Error: Invalid JSON received", file=sys.stderr)
            except EOFError:
                break

    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    finally:
        reader.join(timeout=2)

if __name__ == "__main__":
    main()
