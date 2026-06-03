#!/usr/bin/env python3
"""
Auth Gateway - Bearer Token Validation Proxy
=============================================
Lightweight proxy that validates Bearer tokens before forwarding requests.
Tokens are persisted in a JSON file (survives container restarts).
"""

import os
import json
import hashlib
import secrets
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
import requests
from typing import Optional
import sys

# Configuration
PROXY_URL = os.getenv("PROXY_URL", "http://localhost:3002")
TOKENS_FILE = os.getenv("TOKENS_FILE", "/data/tokens.json")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "80"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")  # Optional: protect admin endpoints

# In-memory token store (loaded from file)
_tokens: dict[str, str] = {}


def load_tokens():
    """Load tokens from persistent file."""
    global _tokens
    try:
        if os.path.exists(TOKENS_FILE):
            with open(TOKENS_FILE, "r") as f:
                _tokens = json.load(f)
            print(f"Loaded {len(_tokens)} token(s) from {TOKENS_FILE}")
        else:
            _tokens = {}
            print(f"No tokens file found at {TOKENS_FILE}, starting empty")
    except Exception as e:
        print(f"Error loading tokens: {e}")
        _tokens = {}


def save_tokens():
    """Save tokens to persistent file."""
    try:
        os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
        with open(TOKENS_FILE, "w") as f:
            json.dump(_tokens, f, indent=2)
        print(f"Saved {len(_tokens)} token(s) to {TOKENS_FILE}")
    except Exception as e:
        print(f"Error saving tokens: {e}")


def generate_token(name: str) -> str:
    """Generate a new token and persist it."""
    token = secrets.token_urlsafe(48)
    _tokens[token] = name
    save_tokens()
    return token


def validate_token(token: str) -> Optional[str]:
    """Validate a Bearer token. Returns the token name if valid, None otherwise."""
    return _tokens.get(token)


def remove_token(token: str) -> bool:
    """Remove a token. Returns True if removed."""
    if token in _tokens:
        del _tokens[token]
        save_tokens()
        return True
    return False


class AuthProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler with Bearer token validation."""

    def log_message(self, format, *args):
        """Override to add timestamp."""
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sys.stdout.write(f"[{timestamp}] {format % args}\n")

    def _send_error(self, code: int, message: str):
        """Send an error response."""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode())

    def _check_admin_auth(self) -> bool:
        """Check if admin endpoint is protected and token is valid."""
        if not ADMIN_TOKEN:
            return True  # No admin protection
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:] == ADMIN_TOKEN
        return False

    def _handle_admin(self):
        """Handle admin endpoints for token management."""
        if not self._check_admin_auth():
            self._send_error(401, "Unauthorized - invalid admin token")
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/admin/tokens" and self.command == "GET":
            # List all tokens (names only, not the actual tokens)
            tokens_list = [{"name": name} for name in _tokens.values()]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"tokens": tokens_list}).encode())

        elif path == "/admin/tokens" and self.command == "POST":
            # Add a new token
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode()
            try:
                data = json.loads(body)
                name = data.get("name", "unnamed")
                token = generate_token(name)
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "token": token,
                    "name": name,
                    "message": "Token created successfully. Save it - it won't be shown again!"
                }).encode())
            except json.JSONDecodeError:
                self._send_error(400, "Invalid JSON")

        elif path.startswith("/admin/tokens/") and self.command == "DELETE":
            # Remove a token (by token value in path)
            token_to_remove = path.split("/")[-1]
            if remove_token(token_to_remove):
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Token removed"}).encode())
            else:
                self._send_error(404, "Token not found")

        elif path == "/admin/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "proxy_url": PROXY_URL,
                "token_count": len(_tokens)
            }).encode())

        else:
            self._send_error(404, "Unknown admin endpoint")

    def _handle_proxy(self):
        """Proxy the request to the backend after validating token."""
        # Extract Bearer token
        auth_header = self.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            self._send_error(401, "Missing or invalid Authorization header. Use: Bearer <token>")
            return

        token = auth_header[7:]  # Remove "Bearer " prefix
        token_name = validate_token(token)

        if token_name is None:
            self._send_error(403, "Invalid token")
            return

        # Token is valid - proxy the request
        target_url = f"{PROXY_URL}{self.path}"
        print(f"[AUTH OK] {token_name} -> {self.command} {self.path}")

        # Forward headers (excluding Host and Authorization)
        headers = {}
        for key, value in self.headers.items():
            if key.lower() not in ("host", "authorization"):
                headers[key] = value

        try:
            # Read request body if present
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            # Make the proxied request
            response = requests.request(
                method=self.command,
                url=target_url,
                headers=headers,
                data=body,
                timeout=60,
                allow_redirects=False
            )

            # Send response back to client
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key.lower() not in ("transfer-encoding", "content-encoding"):
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)

        except requests.exceptions.RequestException as e:
            self._send_error(502, f"Bad Gateway: {str(e)}")

    def do_GET(self):
        """Handle GET requests."""
        if self.path.startswith("/admin"):
            self._handle_admin()
        else:
            self._handle_proxy()

    def do_POST(self):
        """Handle POST requests."""
        if self.path.startswith("/admin"):
            self._handle_admin()
        else:
            self._handle_proxy()

    def do_PUT(self):
        """Handle PUT requests."""
        self._handle_proxy()

    def do_DELETE(self):
        """Handle DELETE requests."""
        if self.path.startswith("/admin"):
            self._handle_admin()
        else:
            self._handle_proxy()

    def do_PATCH(self):
        """Handle PATCH requests."""
        self._handle_proxy()

    def do_HEAD(self):
        """Handle HEAD requests."""
        self._handle_proxy()

    def do_OPTIONS(self):
        """Handle OPTIONS requests."""
        self._handle_proxy()


def main():
    """Start the auth gateway."""
    print(f"Starting Auth Gateway...")
    print(f"Proxy target: {PROXY_URL}")
    print(f"Tokens file: {TOKENS_FILE}")
    print(f"Listening on port: {LISTEN_PORT}")

    if ADMIN_TOKEN:
        print("Admin endpoints protected with ADMIN_TOKEN")
    else:
        print("WARNING: Admin endpoints are unprotected! Set ADMIN_TOKEN env var for production.")

    # Load existing tokens
    load_tokens()

    # Start server
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), AuthProxyHandler)
    print(f"Auth Gateway ready on port {LISTEN_PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
