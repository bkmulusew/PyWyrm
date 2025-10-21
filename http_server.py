import sys
import socket
import os

HOST = '127.0.0.1'  # localhost
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
MAX_CONNECTIONS = 5

BAD_REQUEST_BODY = b"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>400 Bad Request</title>
  </head>
  <body>
    <h1>400 Bad Request</h1>
    <p>Your browser sent a request that this server could not understand.</p>
  </body>
</html>"""

METHOD_NOT_ALLOWED_BODY = b"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>405 Method Not Allowed</title>
  </head>
  <body>
    <h1>405 Method Not Allowed</h1>
    <p>The request method is not allowed for the requested URL.</p>
  </body>
</html>"""

NOT_FOUND_BODY = b"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>404 Not Found</title>
  </head>
  <body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found on this server.</p>
  </body>
</html>"""

FORBIDDEN_BODY = b"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>403 Forbidden</title>
  </head>
  <body>
    <h1>403 Forbidden</h1>
    <p>You don't have permission to access this resource.</p>
  </body>
</html>"""


def http_response(status_line: str, headers: dict, body: bytes) -> bytes:
    head = status_line + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    return head.encode("iso-8859-1") + body

def bad_request_response(body: bytes) -> bytes:
    return http_response(
        "HTTP/1.1 400 Bad Request",
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
        },
        body,
    )

def method_not_allowed_response(body: bytes) -> bytes:
    return http_response(
        "HTTP/1.1 405 Method Not Allowed",
        {
            "Allow": "GET",
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
        },
        body,
    )

def not_found_response(body: bytes) -> bytes:
    return http_response(
        "HTTP/1.1 404 Not Found",
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
        },
        body,
    )

def ok_response(body: bytes) -> bytes:
    return http_response(
        "HTTP/1.1 200 OK",
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
        },
        body,
    )

def forbidden_response(body: bytes) -> bytes:
    return http_response(
        "HTTP/1.1 403 Forbidden",
        {
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
        },
        body,
    )

def run_server(port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # helpful during dev restarts
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        server_socket.bind((HOST, port))
        server_socket.listen(MAX_CONNECTIONS)
        print(f"Serving HTTP on {HOST}:{port} ...\n")

        try:
            while True:
                client_socket, client_address = server_socket.accept()
                with client_socket:
                    print(f"Accepted connection from {client_address}")
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        chunk = client_socket.recv(2048)
                        if not chunk:
                            break
                        buf += chunk

                    if not buf:
                        continue  # no request
                    req = buf.decode("utf-8", errors="replace")

                    # Parse request line: e.g., "GET /sample.html HTTP/1.1"
                    request_line = req.split("\r\n", 1)[0]
                    print(f"Received request: {request_line}")
                    parts = request_line.split()
                    if len(parts) < 3:
                        client_socket.sendall(bad_request_response(BAD_REQUEST_BODY))
                        continue

                    method, path, _ = parts[0], parts[1], parts[2]

                    # Only allow GET (per your code)
                    if method != "GET":
                        client_socket.sendall(method_not_allowed_response(METHOD_NOT_ALLOWED_BODY))
                        continue

                    # Normalize path: strip leading slash, prevent traversal
                    rel_path = path.lstrip("/")
                    if rel_path == "":
                        rel_path = "index.html"  # optional default

                    # Disallow .. to prevent escaping the directory
                    rel_path = os.path.normpath(rel_path)
                    if rel_path.startswith(".."):
                        client_socket.sendall(not_found_response(NOT_FOUND_BODY))
                        continue

                    # Serve from ./<rel_path>
                    file_path = os.path.join(os.getcwd(), rel_path)

                    if os.path.isfile(file_path) and rel_path.lower().endswith(('.html', '.htm')):
                        with open(file_path, "rb") as f:
                            content = f.read()
                        client_socket.sendall(ok_response(content))
                        continue
                    elif os.path.isfile(file_path):
                        client_socket.sendall(forbidden_response(FORBIDDEN_BODY))
                        continue

                    # 404
                    client_socket.sendall(not_found_response(NOT_FOUND_BODY))

        except KeyboardInterrupt:
            print("\nShutting down server gracefully...")
        finally:
            server_socket.close()
            print("Server closed.")
            sys.exit(EXIT_SUCCESS)

if __name__ == "__main__":
    print("Running HTTP server...")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <port>", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    port = int(sys.argv[1].strip())
    run_server(port)