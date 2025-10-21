import socket
import sys
from typing import Dict, Optional

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
MAX_REDIRECTS = 10

class HTTPResponse:
    """
    Minimal container for an HTTP/1.x response.

    - status: numeric status code (e.g., 200, 404)
    - reason: human-readable reason phrase (e.g., "OK", "Not Found")
    - headers: dict of response headers (lowercased header names)
    - body: raw response body bytes
    """
    def __init__(self, status: int, reason: str, headers: Dict[str, str], body: bytes):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        """
        Decode body using charset from Content-Type if present; fallback to UTF-8.
        """
        ct = self.headers.get("content-type", "").lower()
        enc = "utf-8"
        if "charset=" in ct:
            enc = ct.split("charset=", 1)[1].split(":", 1)[0].split(";", 1)[0].strip()
        return self.body.decode(enc, errors="replace")


def get(url: str, headers: Optional[Dict[str, str]] = None) -> HTTPResponse:
    """Convenience wrapper for a simple HTTP GET."""
    return fetch(url, "GET", headers=headers)


def fetch(url: str, method: str, headers: Optional[Dict[str, str]] = None) -> HTTPResponse:
    """
    Perform a single HTTP/1.0 request over a raw TCP socket.
    Only 'http://' is supported (no TLS).
    """
    scheme, rest = url.split("://", 1)
    if scheme != "http":
        print(f"Unsupported scheme: {scheme}", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    # Split host[:port] and path
    host_port, _, path = rest.partition("/")
    
    # Handle IPv6 addresses in URLs like [::1]:8080
    if host_port.startswith('['):
        # IPv6 address format: [host]:port or just [host]
        if ']:' in host_port:
            host_part, port_str = host_port.rsplit(']:', 1)
            host = host_part[1:]  # Remove leading [
            port = int(port_str)
        else:
            host = host_port[1:-1]  # Remove [ and ]
            port = 80
    else:
        # IPv4 address or hostname
        if ':' in host_port:
            host, port_str = host_port.rsplit(':', 1)
            port = int(port_str)
        else:
            host = host_port
            port = 80
    
    path = "/" + path  # ensure leading slash

   # Try to resolve the hostname and connect
    # getaddrinfo returns results for both IPv6 and IPv4
    sock = None
    last_error = None

    try:
        # Get all possible addresses (IPv6 and IPv4)
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)

        # Try each address until one works
        for family, socktype, proto, canonname, sockaddr in addr_info:
            try:
                sock = socket.socket(family, socktype, proto)
                # sock.settimeout(timeout)  # optional timeout if needed
                print(f"Attempting connection to {sockaddr} using {'IPv6' if family == socket.AF_INET6 else 'IPv4'}")
                sock.connect(sockaddr)
                print(f"Connected successfully")
                break
            except socket.error as e:
                if sock:
                    sock.close()
                sock = None
                last_error = e
                continue

        if sock is None:
            raise socket.error(f"Could not connect to {host}:{port} - {last_error}")

    except socket.gaierror as e:
        print(f"Failed to resolve {host}: {e}", file=sys.stderr)
        sys.exit(EXIT_FAILURE)
    except socket.error as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    # Build HTTP/1.0 request lines (server will close after response)
    lines = [
        f"{method} {path} HTTP/1.0",
        f"Host: {host}",
        "User-Agent: MinimalClient/1.0",
    ]
    if headers:
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
    request = "\r\n".join(lines) + "\r\n\r\n"

    # Send and read full response
    sock.sendall(request.encode("utf-8"))
    resp_bytes = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp_bytes += chunk
    sock.close()

    return parse_response(resp_bytes)


def media_type_from_content_type(h: str) -> str:
    """
    Extract the media type from a Content-Type header value.
    - Takes the first value (in case of comma-separated values)
    - Strips parameters like '; charset=utf-8'
    """
    first = h.split(",")[0]
    return first.split(";", 1)[0].strip().lower()


def parse_response(response: bytes) -> HTTPResponse:
    """
    Parse an HTTP/1.x response into status, reason, headers, and body.
    Header bytes are decoded with ISO-8859-1 for a lossless mapping.
    """
    head, body = response.split(b"\r\n\r\n", 1)
    head_lines = head.split(b"\r\n")

    # Status line: e.g., b"HTTP/1.0 200 OK"
    status_line = head_lines[0].decode("iso-8859-1")
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        print(f"Malformed status line: {status_line!r}", file=sys.stderr)
        sys.exit(EXIT_FAILURE)
    version = parts[0]
    status = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""

    # Headers -> dict with lowercased names
    headers: Dict[str, str] = {}
    for raw in head_lines[1:]:
        if not raw or b":" not in raw:
            continue
        name, val = raw.split(b":", 1)
        headers[name.decode("iso-8859-1").strip().lower()] = val.decode("iso-8859-1").lstrip()

    return HTTPResponse(status, reason, headers, body)


# ---- CLI: fetch URL, follow simple redirects, print to stdout/stderr, set exit code ----
if __name__ == "__main__":
    print("Running HTTP client...\n")

    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    url = sys.argv[1].strip()

    try:
        resp = get(url)
        redirects = 0
        while resp.status in (301, 302, 303, 307, 308):
            if redirects > MAX_REDIRECTS:
                print(f"Too many redirects", file=sys.stderr)
                sys.exit(EXIT_FAILURE)
            redirects += 1
            loc = resp.headers.get("location")
            if not loc:
                print(f"Redirect with no Location header", file=sys.stderr)
                sys.exit(EXIT_FAILURE)
            print(f"Redirecting to {loc}")
            resp = get(loc)
    except Exception as e:
        print(f"Request failed: {e}", file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    ct = resp.headers.get("content-type", "").lower()
    mt = media_type_from_content_type(ct)

    if resp.status == 200 and mt == "text/html":
        print(resp.text)
        sys.exit(EXIT_SUCCESS)
    elif resp.status == 200:
        print(f"Request failed: {resp.status} {resp.reason}, expected text/html, got {mt}", file=sys.stderr)
        sys.exit(EXIT_FAILURE)
    else:
        print(f"Request failed: {resp.status} {resp.reason}", file=sys.stderr)
        sys.exit(EXIT_FAILURE)