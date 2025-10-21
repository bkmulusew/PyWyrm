import socket
import sys
from typing import Dict, Tuple, Optional

class HTTPResponse:
    def __init__(self, status: int, reason: str, headers: Dict[str, str], body: bytes):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        ct = self.headers.get("content-type", "").lower()
        enc = "utf-8"
        if "charset=" in ct:
            enc = ct.split("charset=", 1)[1].split(";", 1)[0].strip()
        return self.body.decode(enc, errors="replace")

def get(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 10.0) -> HTTPResponse:
    return fetch(url, "GET", headers=headers, timeout=timeout)

def fetch(url: str, method: str, headers: Optional[Dict[str, str]] = None, timeout: float = 10.0) -> HTTPResponse:
    scheme, rest = url.split("://", 1)
    host_port, _, path = rest.partition("/")
    host, port = (host_port, 80)
    if ":" in host_port:
        host, port_str = host_port.split(":", 1)
        port = int(port_str)
    path = "/" + path  # ensure leading slash

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))

    # Build a valid HTTP/1.0 request (auto-closes connection after response)
    lines = [
        f"{method} {path} HTTP/1.0",
        f"Host: {host}",
        "User-Agent: MinimalClient/1.0",
    ]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    request = "\r\n".join(lines) + "\r\n\r\n"

    sock.sendall(request.encode("utf-8"))

    # Read full response
    resp_bytes = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp_bytes += chunk
    sock.close()

    return parse_response(resp_bytes)

def parse_response(response: bytes) -> HTTPResponse:
    head, body = response.split(b"\r\n\r\n", 1)
    head_lines = head.split(b"\r\n")
    status_line = head_lines[0].decode("iso-8859-1")

    # e.g., "HTTP/1.0 200 OK"
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        raise ValueError(f"Malformed status line: {status_line!r}")
    version = parts[0]
    status = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""

    headers: Dict[str, str] = {}
    for raw in head_lines[1:]:
        if not raw or b":" not in raw:
            continue
        name, val = raw.split(b":", 1)
        headers[name.decode("iso-8859-1").strip().lower()] = val.decode("iso-8859-1").lstrip()

    return HTTPResponse(status, reason, headers, body)

# ---- Run and return proper Unix exit code ----
if __name__ == "__main__":
    print("Running HTTP client...")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>", file=sys.stderr)
        sys.exit(2)  # 2 = bad invocation/usage

    url = sys.argv[1]
    resp = get(url)
    print(resp.text)
    # Exit 0 if 200 OK, else non-zero (use status code if you like; 1 is fine too)
    sys.exit(0 if resp.status == 200 else 1)