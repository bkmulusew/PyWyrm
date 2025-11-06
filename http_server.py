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
import select
from typing import Dict, Tuple, Optional

HOST_V4 = "127.0.0.1"   # IPv4 loopback
HOST_V6 = "::1"         # IPv6 loopback
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
MAX_BACKLOG = 5
READ_CHUNK = 2048
REQ_HEADER_LIMIT = 64 * 1024  # simple guardrail for header size DoS
DEFAULT_ENCODING = "utf-8"

ALLOWED_METHOD = "GET"
ALLOWED_HTML_EXTS = (".html", ".htm")

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

class Connection:
    """
    State machine for a single client connection.
    Tracks request buffer, response buffer, and connection state.
    """
    def __init__(self, socket: socket.socket, address):
        self.socket = socket
        self.address = address
        self.request_buffer = b""
        self.response_buffer = b""
        self.headers_complete = False
        self.should_close = False

def setup_server(port: int, backlog: int) -> socket.socket:
    """
    Create a listening socket.
    Tries IPv6 loopback (::1) with dual-stack (IPv4-mapped) when supported,
    otherwise falls back to IPv4 loopback.
    """
    # Try IPv6 dual-stack first
    try:
        server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # Some OSes forbid toggling this; ignore if unsupported.
            server_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError as e:
            print(f"[warn] IPV6_V6ONLY=0 not supported: {e}")

        server_socket.bind((HOST_V6, port))
        server_socket.listen(backlog)
        print(f"[ok] Listening on IPv6 {HOST_V6}:{port} (dual-stack if supported)\n")
        return server_socket
    except OSError as e:
        print(f"[warn] IPv6 bind failed: {e}. Falling back to IPv4...")

    # Fallback: IPv4 only
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST_V4, port))
    server_socket.listen(backlog)
    print(f"[ok] Listening on IPv4 {HOST_V4}:{port}")
    return server_socket

def read_http_request(conn: Connection) -> bool:
    """
    Non-blocking read of HTTP request data.
    Returns True if headers are complete, False otherwise.
    """
    if conn.headers_complete:
        return True

    try:
        chunk = conn.socket.recv(READ_CHUNK)
        if not chunk:
            # Connection closed by client
            conn.should_close = True
            return False

        conn.request_buffer += chunk

        # Check if we have complete headers
        if b"\r\n\r\n" in conn.request_buffer:
            conn.headers_complete = True
            return True

        # Check size limit
        if len(conn.request_buffer) > REQ_HEADER_LIMIT:
            # Request too large
            conn.response_buffer = bad_request_response()
            conn.should_close = True
            return True

    except socket.error as e:
        # Would block or other error
        if e.errno not in (socket.EWOULDBLOCK, socket.EAGAIN):
            conn.should_close = True

    return False

def parse_request_line(line: str) -> Tuple[str, str, str]:
    """
    Parse: 'METHOD /path HTTP/1.1' -> (method, path, version).
    Returns empty strings if malformed.
    """
    parts = line.split()
    if len(parts) < 3:
        return "", "", ""
    return parts[0], parts[1], parts[2]

def process_request(conn: Connection) -> None:
    """
    Process complete request headers and generate response.
    """
    if not conn.headers_complete:
        return

    # Parse request
    request = conn.request_buffer.decode(DEFAULT_ENCODING, errors="replace")
    first_line = request.split("\r\n", 1)[0]

    print(f"[{conn.address}] Request: {first_line}")

    # Generate response
    conn.response_buffer = build_response(first_line)
    conn.should_close = True  # HTTP/1.0 style - close after response

def write_response(conn: Connection) -> bool:
    """
    Non-blocking write of response data.
    Returns True if all data sent, False otherwise.
    """
    if not conn.response_buffer:
        return True

    try:
        sent = conn.socket.send(conn.response_buffer)
        conn.response_buffer = conn.response_buffer[sent:]

        if not conn.response_buffer:
            # All data sent
            return True

    except socket.error as e:
        if e.errno not in (socket.EWOULDBLOCK, socket.EAGAIN):
            conn.should_close = True
            return True

    return False

def http_response(status_line: str, headers: Dict[str, str], body: bytes) -> bytes:
    """Build a raw HTTP response message."""
    head = status_line + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    return head.encode(DEFAULT_ENCODING) + body

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

def build_response(request: str) -> None:
    """Generate HTTP response for a request."""
    method, path, _version = parse_request_line(request)
    if not method:
        return bad_request_response()

    # Only allow GET
    if method != ALLOWED_METHOD:
        return method_not_allowed_response()

    # Resolve path safely
    rel_path = safe_filesystem_path(path)
    if not rel_path:
        return not_found_response()

    # Serve file (HTML only) / or 403/404
    return serve_file_if_allowed(rel_path)

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

def run_server(port: int) -> None:
    """
    Run the server using select() for I/O multiplexing.
    Handles multiple concurrent connections without blocking.
    """
    server_socket: Optional[socket.socket] = None
    connections: Dict[socket.socket, Connection] = {}

    try:
        server_socket = setup_server(port, MAX_BACKLOG)
        server_socket.setblocking(False)  # Non-blocking mode

        print("Server ready. Waiting for connections... (Ctrl-C to stop)\n")

        while True:
            # Build socket lists for select
            read_sockets = [server_socket]
            write_sockets = []

            for sock, conn in connections.items():
                if not conn.headers_complete or conn.request_buffer:
                    read_sockets.append(sock)
                if conn.response_buffer:
                    write_sockets.append(sock)

            try:
                # Wait for I/O activity
                readable, writable, _ = select.select(
                    read_sockets, write_sockets, []
                )
            except select.error:
                continue

            # Handle new connections
            if server_socket in readable:
                try:
                    client_socket, client_address = server_socket.accept()
                    client_socket.setblocking(False)
                    connections[client_socket] = Connection(client_socket, client_address)
                    print(f"[+] New connection from {client_address}")
                except socket.error:
                    pass

            # Handle readable client sockets
            for sock in readable:
                if sock != server_socket and sock in connections:
                    conn = connections[sock]
                    if read_http_request(conn):
                        process_request(conn)

            # Handle writable client sockets
            for sock in writable:
                if sock in connections:
                    conn = connections[sock]
                    if write_response(conn):
                        if conn.should_close:
                            # Response complete, close connection
                            print(f"[-] Closing connection from {conn.address}")
                            sock.close()
                            del connections[sock]

            # Clean up connections that should be closed
            to_remove = []
            for sock, conn in connections.items():
                if conn.should_close and not conn.response_buffer:
                    to_remove.append(sock)

            for sock in to_remove:
                print(f"[-] Removing connection from {connections[sock].address}")
                sock.close()
                del connections[sock]

    except KeyboardInterrupt:
        print("\n\nShutting down server gracefully...")

    except Exception as e:
        print(f"[error] Server error: {e}")

    finally:
        # Clean up all connections
        for sock in connections:
            try:
                sock.close()
            except:
                pass

        if server_socket:
            try:
                server_socket.close()
            except:
                pass

        print("Server closed.")
        sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    print("Starting HTTP server...\n")
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <port>", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    try:
        port = int(sys.argv[1].strip())
        if not (1 <= port <= 65535):
            raise ValueError("Port must be between 1 and 65535")
    except ValueError as e:
        print(f"Invalid port: {e}", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    run_server(port)
