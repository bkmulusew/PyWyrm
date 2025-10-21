#!/usr/bin/env python3
"""
Tiny single-file HTTP 1.1 server for local testing.

- Listens on IPv6 loopback (::1) with IPv4-mapped support when available;
  falls back to IPv4 (127.0.0.1) if IPv6 bind fails.
- Serves only GET requests.
- Serves only .html/.htm files under the current working directory.
- Blocks directory traversal attempts ("..").
- Returns simple HTML error pages for 400/403/404/405.
"""

import os
import sys
import socket
from typing import Dict, Tuple

# ----------------------------- Constants -------------------------------------

HOST_V4 = "127.0.0.1"   # IPv4 loopback
HOST_V6 = "::1"         # IPv6 loopback
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
MAX_CONNECTIONS = 5
READ_CHUNK = 2048
REQ_HEADER_LIMIT = 64 * 1024  # simple guardrail for header size DoS

ALLOWED_METHOD = "GET"
ALLOWED_HTML_EXTS = (".html", ".htm")

# ----------------------------- Error Pages -----------------------------------

BAD_REQUEST_BODY = b"""<!DOCTYPE html>
<html lang="en">
  <head><meta charset="utf-8"><title>400 Bad Request</title></head>
  <body><h1>400 Bad Request</h1><p>Your browser sent a request that this server could not understand.</p></body>
</html>"""

METHOD_NOT_ALLOWED_BODY = b"""<!DOCTYPE html>
<html lang="en">
  <head><meta charset="utf-8"><title>405 Method Not Allowed</title></head>
  <body><h1>405 Method Not Allowed</h1><p>The request method is not allowed for the requested URL.</p></body>
</html>"""

NOT_FOUND_BODY = b"""<!DOCTYPE html>
<html lang="en">
  <head><meta charset="utf-8"><title>404 Not Found</title></head>
  <body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body>
</html>"""

FORBIDDEN_BODY = b"""<!DOCTYPE html>
<html lang="en">
  <head><meta charset="utf-8"><title>403 Forbidden</title></head>
  <body><h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p></body>
</html>"""

# -------------------------- HTTP Response Helpers ----------------------------

def http_response(status_line: str, headers: Dict[str, str], body: bytes) -> bytes:
    """Build a raw HTTP response message."""
    head = status_line + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    return head.encode("iso-8859-1") + body

def bad_request_response(body: bytes = BAD_REQUEST_BODY) -> bytes:
    return http_response(
        "HTTP/1.1 400 Bad Request",
        {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body)), "Connection": "close"},
        body,
    )

def method_not_allowed_response(body: bytes = METHOD_NOT_ALLOWED_BODY) -> bytes:
    return http_response(
        "HTTP/1.1 405 Method Not Allowed",
        {
            "Allow": ALLOWED_METHOD,
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
        },
        body,
    )

def not_found_response(body: bytes = NOT_FOUND_BODY) -> bytes:
    return http_response(
        "HTTP/1.1 404 Not Found",
        {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body)), "Connection": "close"},
        body,
    )

def forbidden_response(body: bytes = FORBIDDEN_BODY) -> bytes:
    return http_response(
        "HTTP/1.1 403 Forbidden",
        {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body)), "Connection": "close"},
        body,
    )

def ok_response(body: bytes) -> bytes:
    return http_response(
        "HTTP/1.1 200 OK",
        {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body)), "Connection": "close"},
        body,
    )

# ------------------------------ Networking -----------------------------------

def make_listening_socket(port: int, backlog: int) -> socket.socket:
    """
    Create a listening socket.
    Tries IPv6 loopback (::1) with dual-stack (IPv4-mapped) when supported,
    otherwise falls back to IPv4 loopback.
    """
    # Try IPv6 dual-stack first
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # Some OSes forbid toggling this; ignore if unsupported.
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError as e:
            print(f"[warn] IPV6_V6ONLY=0 not supported: {e}")

        s.bind((HOST_V6, port))
        s.listen(backlog)
        print(f"[ok] Listening on IPv6 {HOST_V6}:{port} (dual-stack if supported)\n")
        return s
    except OSError as e:
        print(f"[warn] IPv6 bind failed: {e}. Falling back to IPv4...")

    # Fallback: IPv4 only
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST_V4, port))
    s.listen(backlog)
    print(f"[ok] Listening on IPv4 {HOST_V4}:{port}")
    return s

# ------------------------------ Request I/O ----------------------------------

def read_http_request(sock: socket.socket) -> Tuple[str, str]:
    """
    Read raw HTTP header bytes until CRLFCRLF and return:
    (first_request_line, full_request_text).
    """
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(READ_CHUNK)
        if not chunk:
            break
        buf += chunk
        if len(buf) > REQ_HEADER_LIMIT:
            # Prevent unbounded growth on malicious/buggy clients.
            return "", ""

    if not buf:
        return "", ""

    text = buf.decode("utf-8", errors="replace")
    first_line = text.split("\r\n", 1)[0]
    return first_line, text

def parse_request_line(line: str) -> Tuple[str, str, str]:
    """
    Parse: 'METHOD /path HTTP/1.1' -> (method, path, version).
    Returns empty strings if malformed.
    """
    parts = line.split()
    if len(parts) < 3:
        return "", "", ""
    return parts[0], parts[1], parts[2]

# ------------------------------ Routing --------------------------------------

def safe_filesystem_path(url_path: str) -> str:
    """
    Convert a URL path to a safe relative filesystem path rooted at CWD.
    - Strips leading slash
    - Normalizes path
    - Rejects traversal (..)
    """
    rel_path = url_path.lstrip("/")
    if rel_path == "":
        rel_path = "index.html"  # default document
    rel_path = os.path.normpath(rel_path)
    if rel_path.startswith(".."):
        return ""  # signal invalid
    return rel_path

def serve_file_if_allowed(rel_path: str) -> bytes:
    """
    Return an HTTP response for a file request:
    - 200 for existing .html/.htm files
    - 403 for existing non-HTML files
    - 404 for non-existent files
    """
    file_path = os.path.join(os.getcwd(), rel_path)

    if os.path.isfile(file_path):
        if rel_path.lower().endswith(ALLOWED_HTML_EXTS):
            with open(file_path, "rb") as f:
                return ok_response(f.read())
        return forbidden_response()

    return not_found_response()

# ------------------------------ Main Server ----------------------------------

def handle_client(client_socket: socket.socket, client_address) -> None:
    """Handle a single client connection lifecycle."""
    print(f"Accepted connection from {client_address}")

    # Read and parse request line
    request_line, _full = read_http_request(client_socket)
    if not request_line:
        return  # ignore empty or oversized header

    print(f"Received request: {request_line}")
    method, path, _version = parse_request_line(request_line)
    if not method:
        client_socket.sendall(bad_request_response())
        return

    # Only allow GET
    if method != ALLOWED_METHOD:
        client_socket.sendall(method_not_allowed_response())
        return

    # Resolve path safely
    rel_path = safe_filesystem_path(path)
    if not rel_path:
        client_socket.sendall(not_found_response())
        return

    # Serve file (HTML only) / or 403/404
    client_socket.sendall(serve_file_if_allowed(rel_path))

def run_server(port: int) -> None:
    """Run the accept loop; Ctrl-C to stop."""
    server_socket: socket.socket | None = None
    try:
        server_socket = make_listening_socket(port, MAX_CONNECTIONS)

        try:
            while True:
                client_socket, client_address = server_socket.accept()
                # No threading: handle sequentially for simplicity.
                with client_socket:
                    handle_client(client_socket, client_address)

        except KeyboardInterrupt:
            print("\nShutting down server gracefully...")
            sys.exit(EXIT_SUCCESS)

    except Exception as e:
        print(f"[error] Server crashed: {e}")

    finally:
        if server_socket is not None:
            try:
                server_socket.close()
            except Exception:
                pass
        print("Server closed.")

# --------------------------------- Entrypoint --------------------------------

if __name__ == "__main__":
    print("Running HTTP server...")
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <port>", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    try:
        port = int(sys.argv[1].strip())
    except ValueError:
        print("Port must be an integer.", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    run_server(port)
