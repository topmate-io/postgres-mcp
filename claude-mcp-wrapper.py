#!/usr/bin/env python3
"""
MCP Stdio to HTTP/SSE Bridge
Allows Claude Desktop to communicate with remote MCP servers via HTTP/SSE
Uses separate threads for stdin reading and SSE reading to properly handle bidirectional communication
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
                        output_queue.put(('sse', data))
                    except json.JSONDecodeError:
                        pass

        process.wait()
    except Exception as e:
        output_queue.put(('error', str(e)))

def stdin_reader_thread(input_queue: queue.Queue):
    """Read from stdin"""
    try:
        for line in sys.stdin:
            line = line.strip()
            if line:
                input_queue.put(line)
    except Exception as e:
        input_queue.put(None)  # Signal EOF

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

        subprocess.run(curl_cmd, capture_output=True, timeout=5)
    except Exception:
        pass  # Silently ignore send errors

def main():
    """Main entry point"""
    token = get_auth_token()
    base_url = "https://postgres-mcp-49979260925.asia-south1.run.app"
    session_id = str(uuid.uuid4())

    output_queue = queue.Queue()
    input_queue = queue.Queue()

    # Start SSE reader thread
    sse_thread = threading.Thread(
        target=sse_reader_thread,
        args=(token, base_url, session_id, output_queue),
        daemon=False
    )
    sse_thread.start()

    # Start stdin reader thread
    stdin_thread = threading.Thread(
        target=stdin_reader_thread,
        args=(input_queue,),
        daemon=False
    )
    stdin_thread.start()

    try:
        while True:
            # Check for input from stdin (non-blocking)
            try:
                line = input_queue.get_nowait()
                if line is None:
                    # stdin closed
                    break
                try:
                    message_obj = json.loads(line)
                    send_message_to_server(token, base_url, session_id, message_obj)
                except json.JSONDecodeError:
                    pass
            except queue.Empty:
                pass

            # Check for output from SSE reader (non-blocking)
            try:
                event_type, data = output_queue.get_nowait()
                if event_type == 'sse':
                    sys.stdout.write(data + '\n')
                    sys.stdout.flush()
                elif event_type == 'error':
                    pass  # Silently log errors
            except queue.Empty:
                pass

            # Small sleep to avoid busy waiting
            time.sleep(0.01)

    except KeyboardInterrupt:
        pass
    except Exception:
        pass  # Exit silently
    finally:
        sse_thread.join(timeout=2)
        stdin_thread.join(timeout=2)

if __name__ == "__main__":
    main()
