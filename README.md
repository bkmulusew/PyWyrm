# PyWyrm 🐍

A lightweight HTTP server and client implementation in Python using raw sockets.

## Overview

PyWyrm is a minimal HTTP implementation built for learning network programming fundamentals. No external dependencies, no frameworks - just pure Python and sockets.

## Features

- **HTTP Server**: Simple HTTP/1.1 server with GET method support
- **HTTP Client**: Minimal client with automatic redirect following  
- **Dual Stack**: IPv4 and IPv6 support
- **Zero Dependencies**: Uses only Python standard library

## Quick Start

### Server
```bash
python http_server.py 8080
```

### Client
```bash
python http_client.py http://localhost:8080/index.html
```

## Why PyWyrm?

Perfect for understanding how HTTP works under the hood without the complexity of production frameworks.
