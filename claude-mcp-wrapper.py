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
            f.write(f"{msg}\n")
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
        log("Got auth token")
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
        log(f"Starting SSE reader with session {session_id}")
        process = subprocess.Popen(
            curl_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1  # Line buffered
        )

        log("SSE process started")
        current_event = None
        line_count = 0
        for line in iter(process.stdout.readline, ''):
            line = line.rstrip('\n')
            if not line:
                # Blank line = end of SSE event, reset state
                current_event = None
                continue

            line_count += 1
            if line.startswith('event: '):
                current_event = line[7:].strip()
                log(f"SSE event {line_count}: {current_event}")
            elif line.startswith('data: '):
                data = line[6:].strip()
                if data:
                    if current_event == 'endpoint':
                        # Server sends endpoint URL - put it in queue so main thread can use it
                        output_queue.put(('endpoint', data))
                        log(f"Got endpoint: {data}")
                    elif current_event == 'message' or not current_event:
                        # MCP response message (either with event: message or without event header)
                        try:
                            json.loads(data)  # Validate JSON
                            output_queue.put(('sse', data))
                            log(f"Queued MCP response")
                        except json.JSONDecodeError as e:
                            log(f"Invalid JSON in response: {e}")
                    else:
                        # Some other event type we don't recognize, skip it
                        log(f"Skipping unrecognized event type: {current_event}")

        log("SSE process ended")
        returncode = process.wait()
        log(f"SSE process exit code: {returncode}")
        if returncode != 0:
            stderr = process.stderr.read()
            log(f"SSE stderr: {stderr}")
            output_queue.put(('sse_closed', f'SSE stream closed with code {returncode}'))
        else:
            output_queue.put(('sse_closed', 'SSE stream closed normally'))
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
                input_queue.put(line)
        log("Stdin closed")
        input_queue.put(None)  # Signal EOF
    except Exception as e:
        log(f"Stdin reader error: {e}")
        log(traceback.format_exc())
        input_queue.put(None)

def send_message_to_server(token: str, base_url: str, endpoint_path: str, message: dict):
    """Send a message to the server using curl"""
    try:
        # Use the endpoint path provided by the server (e.g., "/messages/?session_id=...")
        full_url = f"{base_url}{endpoint_path}"
        curl_cmd = [
            "curl", "-s", "-L",
            "-X", "POST",
            "-H", f"Authorization: Bearer {token}",
            "-H", "Content-Type: application/json",
            "-d", json.dumps(message),
            full_url
        ]

        log(f"Sending: method={message.get('method')}")
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=5)
        log(f"Message sent (code {result.returncode})")
        if result.returncode != 0:
            log(f"Error: {result.stderr}")
    except Exception as e:
        log(f"Send error: {e}")

def main():
    """Main entry point"""
    try:
        log("Wrapper starting")
        token = get_auth_token()
        base_url = "https://postgres-mcp-49979260925.asia-south1.run.app"
        session_id = str(uuid.uuid4())
        log(f"Session: {session_id}")

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
        log("Threads started")

        # The server will send us the actual endpoint URL and session ID via SSE
        message_endpoint = None
        pending_messages = []  # Queue messages until endpoint arrives
        endpoint_timeout = time.time() + 10  # Wait max 10 seconds for endpoint
        endpoint_received = False
        sse_stream_alive = True

        log("Ready to process messages")

        while True:
            try:
                # Check for output from SSE reader first (non-blocking)
                try:
                    event_type, data = output_queue.get_nowait()
                    if event_type == 'endpoint':
                        # Capture the endpoint URL from the server
                        message_endpoint = data
                        endpoint_received = True
                        log(f"Using endpoint: {message_endpoint}")
                        # Process any pending messages now that we have the endpoint
                        for msg in pending_messages:
                            send_message_to_server(token, base_url, message_endpoint, msg)
                        pending_messages = []
                    elif event_type == 'sse':
                        log(f"Got response")
                        sys.stdout.write(data + '\n')
                        sys.stdout.flush()
                    elif event_type == 'error':
                        log(f"SSE error: {data}")
                        sse_stream_alive = False
                    elif event_type == 'sse_closed':
                        log(f"SSE stream closed: {data}")
                        sse_stream_alive = False
                except queue.Empty:
                    pass

                # Check for timeout waiting for endpoint
                if not endpoint_received and time.time() > endpoint_timeout:
                    log("Timeout: No endpoint received from server after 10 seconds")
                    # Send error to Claude Desktop
                    error_response = {
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32603,
                            "message": "MCP server endpoint not received"
                        }
                    }
                    sys.stdout.write(json.dumps(error_response) + '\n')
                    sys.stdout.flush()
                    sse_stream_alive = False

                # Check for input from stdin (non-blocking)
                try:
                    line = input_queue.get_nowait()
                    # Skip None (EOF marker from stdin thread)
                    if line is not None:
                        try:
                            message_obj = json.loads(line)
                            log(f"Input: {message_obj.get('method')}")
                            # Queue message if endpoint not ready, or send immediately if ready
                            if message_endpoint:
                                send_message_to_server(token, base_url, message_endpoint, message_obj)
                            else:
                                log("Queuing message until endpoint is available")
                                pending_messages.append(message_obj)
                        except json.JSONDecodeError as e:
                            log(f"JSON error: {e}")
                except queue.Empty:
                    pass

                # Exit if SSE stream is dead and we have no more messages to process
                if not sse_stream_alive and not pending_messages:
                    log("SSE stream closed and no pending messages, exiting")
                    break

                time.sleep(0.01)
            except Exception as e:
                log(f"Loop error: {e}")
                log(traceback.format_exc())

    except KeyboardInterrupt:
        log("Interrupted")
    except Exception as e:
        log(f"Main error: {e}")
        log(traceback.format_exc())
    finally:
        log("Shutdown")

if __name__ == "__main__":
    main()
