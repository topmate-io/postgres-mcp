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
import traceback

LOG_FILE = "/tmp/mcp-wrapper.log"

def log(msg):
    """Log to both stderr and a file for debugging"""
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{time.time()}: {msg}\n")
            f.flush()
    except:
        pass
    try:
        print(f"[LOG] {msg}", file=sys.stderr, flush=True)
    except:
        pass

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
        log(f"Got auth token: {token[:20]}...")
        return token
    except Exception as e:
        log(f"Auth failed: {e}")
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
        log(f"Starting SSE reader for session {session_id}")
        process = subprocess.Popen(
            curl_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )

        log("SSE process started")
        current_event = None
        for line in iter(process.stdout.readline, ''):
            line = line.rstrip('\n')
            if not line:
                continue

            if line.startswith('event: '):
                current_event = line[7:].strip()
                log(f"SSE event: {current_event}")
            elif line.startswith('data: '):
                data = line[6:].strip()
                if data and current_event != 'endpoint':
                    try:
                        json.loads(data)  # Validate JSON
                        output_queue.put(('sse', data))
                        log(f"Queued SSE response: {data[:50]}...")
                    except json.JSONDecodeError as e:
                        log(f"Invalid JSON from SSE: {data[:50]}... ({e})")

        log("SSE process ended")
        process.wait()
    except Exception as e:
        log(f"SSE reader error: {e}")
        log(traceback.format_exc())
        output_queue.put(('error', str(e)))

def stdin_reader_thread(input_queue: queue.Queue):
    """Read from stdin"""
    try:
        log("Stdin reader starting")
        for line in sys.stdin:
            line = line.strip()
            if line:
                log(f"Stdin input: {line[:50]}...")
                input_queue.put(line)
        log("Stdin closed")
        input_queue.put(None)  # Signal EOF
    except Exception as e:
        log(f"Stdin reader error: {e}")
        log(traceback.format_exc())
        input_queue.put(None)

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

        log(f"Sending message: {json.dumps(message)[:50]}...")
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=5)
        log(f"Message sent, return code: {result.returncode}")
        if result.returncode != 0:
            log(f"Post error: {result.stderr}")
    except Exception as e:
        log(f"Send error: {e}")

def main():
    """Main entry point"""
    try:
        log("Wrapper starting")
        token = get_auth_token()
        base_url = "https://postgres-mcp-49979260925.asia-south1.run.app"
        session_id = str(uuid.uuid4())
        log(f"Using session ID: {session_id}")

        output_queue = queue.Queue()
        input_queue = queue.Queue()

        # Start SSE reader thread
        sse_thread = threading.Thread(
            target=sse_reader_thread,
            args=(token, base_url, session_id, output_queue),
            daemon=False
        )
        sse_thread.start()
        log("SSE thread started")

        # Start stdin reader thread
        stdin_thread = threading.Thread(
            target=stdin_reader_thread,
            args=(input_queue,),
            daemon=False
        )
        stdin_thread.start()
        log("Stdin thread started")

        loop_count = 0
        while True:
            loop_count += 1
            if loop_count % 1000 == 0:
                log(f"Main loop running ({loop_count} iterations)")

            # Check for input from stdin (non-blocking)
            try:
                line = input_queue.get_nowait()
                if line is None:
                    log("Got EOF from stdin, exiting")
                    break
                log(f"Processing stdin line (len={len(line)}): {line}")
                try:
                    message_obj = json.loads(line)
                    log(f"Parsed JSON successfully: method={message_obj.get('method')}")
                    send_message_to_server(token, base_url, session_id, message_obj)
                except json.JSONDecodeError as e:
                    log(f"Invalid JSON from stdin: {e}, line={line}")
            except queue.Empty:
                pass

            # Check for output from SSE reader (non-blocking)
            try:
                event_type, data = output_queue.get_nowait()
                if event_type == 'sse':
                    log(f"Writing to stdout: {data[:50]}...")
                    sys.stdout.write(data + '\n')
                    sys.stdout.flush()
                elif event_type == 'error':
                    log(f"SSE error: {data}")
            except queue.Empty:
                pass

            # Small sleep to avoid busy waiting
            time.sleep(0.01)

    except KeyboardInterrupt:
        log("Interrupted")
    except Exception as e:
        log(f"Main error: {e}")
        log(traceback.format_exc())
    finally:
        log("Wrapper shutting down")

if __name__ == "__main__":
    main()
