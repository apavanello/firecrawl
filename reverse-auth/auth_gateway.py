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
import hmac
import logging
import secrets
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests
from typing import Optional

# Logging setup
DEBUG_MODE = os.getenv("DEBUG", "false").lower() in ("1", "true", "yes")
logging.basicConfig(
    level=logging.DEBUG if DEBUG_MODE else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger("auth-gateway")

# Configuration
PROXY_URL = os.getenv("PROXY_URL", "http://localhost:3002")
TOKENS_FILE = os.getenv("TOKENS_FILE", "/data/tokens.json")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "80"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")  # Optional: protect admin endpoints
MAX_ADMIN_BODY = 1024  # 1 KB max for admin requests
MAX_PROXY_BODY = 10 * 1024 * 1024  # 10 MB max for proxied requests

# In-memory token store (loaded from file)
_tokens: dict[str, str] = {}


def load_tokens():
    """Load tokens from persistent file."""
    global _tokens
    try:
        if os.path.exists(TOKENS_FILE):
            log.debug("Reading tokens file: %s", TOKENS_FILE)
            with open(TOKENS_FILE, "r") as f:
                _tokens = json.load(f)
            log.info("Loaded %d token(s) from %s", len(_tokens), TOKENS_FILE)
            log.debug("Token hashes in store: %s", [h[:12] + '...' for h in _tokens.keys()])
        else:
            _tokens = {}
            log.info("No tokens file found at %s, starting empty", TOKENS_FILE)
    except Exception as e:
        log.error("Error loading tokens from %s: %s", TOKENS_FILE, e, exc_info=DEBUG_MODE)
        _tokens = {}


def save_tokens():
    """Save tokens to persistent file."""
    try:
        os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
        log.debug("Writing %d token(s) to %s", len(_tokens), TOKENS_FILE)
        with open(TOKENS_FILE, "w") as f:
            json.dump(_tokens, f, indent=2)
        log.info("Saved %d token(s) to %s", len(_tokens), TOKENS_FILE)
    except Exception as e:
        log.error("Error saving tokens to %s: %s", TOKENS_FILE, e, exc_info=DEBUG_MODE)


def _hash_token(token: str) -> str:
    """Hash a token with SHA-256 for secure storage."""
    hashed = hashlib.sha256(token.encode()).hexdigest()
    log.debug("Hashed token -> %s...", hashed[:12])
    return hashed


def generate_token(name: str) -> str:
    """Generate a new token and persist its hash."""
    token = secrets.token_urlsafe(48)
    hashed = _hash_token(token)
    _tokens[hashed] = name
    log.info("Generated new token for '%s' (hash: %s...)", name, hashed[:12])
    save_tokens()
    return token


def validate_token(token: str) -> Optional[str]:
    """Validate a Bearer token. Returns the token name if valid, None otherwise."""
    result = _tokens.get(_hash_token(token))
    if result:
        log.debug("Token validated successfully -> owner: '%s'", result)
    else:
        log.debug("Token validation failed — no matching hash in store")
    return result


def remove_token(token: str) -> bool:
    """Remove a token by its raw value. Returns True if removed."""
    hashed = _hash_token(token)
    if hashed in _tokens:
        name = _tokens[hashed]
        del _tokens[hashed]
        log.info("Removed token '%s' (hash: %s...)", name, hashed[:12])
        save_tokens()
        return True
    log.debug("Token removal failed — hash %s... not found", hashed[:12])
    return False


class AuthProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler with Bearer token validation."""

    def log_message(self, format, *args):
        """Route BaseHTTPRequestHandler logs through our logger."""
        log.info(format, *args)

    def _send_error(self, code: int, message: str):
        """Send an error response."""
        log.warning("Responding %d: %s [%s %s]", code, message, self.command, self.path)
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode())

    def _check_admin_auth(self) -> bool:
        """Check if admin endpoint is protected and token is valid."""
        if not ADMIN_TOKEN:
            log.debug("Admin auth: no ADMIN_TOKEN set, allowing unrestricted access")
            return True  # No admin protection
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            is_valid = hmac.compare_digest(auth_header[7:], ADMIN_TOKEN)
            log.debug("Admin auth: Bearer token provided, valid=%s", is_valid)
            return is_valid
        log.debug("Admin auth: no Bearer token in Authorization header")
        return False

    def _handle_admin(self):
        """Handle admin endpoints for token management."""
        log.debug("Admin request: %s %s", self.command, self.path)
        if not self._check_admin_auth():
            self._send_error(401, "Unauthorized - invalid admin token")
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/admin/tokens" and self.command == "GET":
            # List all tokens (names only, not the actual tokens)
            tokens_list = [{"name": name} for name in _tokens.values()]
            log.debug("Admin list tokens: returning %d token(s)", len(tokens_list))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"tokens": tokens_list}).encode())

        elif path == "/admin/tokens" and self.command == "POST":
            # Add a new token
            content_length = int(self.headers.get("Content-Length", 0))
            log.debug("Admin create token: Content-Length=%d", content_length)
            if content_length > MAX_ADMIN_BODY:
                log.warning("Admin create token: body too large (%d > %d)", content_length, MAX_ADMIN_BODY)
                self._send_error(413, "Request body too large")
                return
            body = self.rfile.read(content_length).decode()
            log.debug("Admin create token: body=%s", body)
            try:
                data = json.loads(body)
                name = data.get("name", "unnamed")
                token = generate_token(name)
                log.info("Admin created token for '%s'", name)
                self.send_response(201)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "token": token,
                    "name": name,
                    "message": "Token created successfully. Save it - it won't be shown again!"
                }).encode())
            except json.JSONDecodeError:
                log.debug("Admin create token: invalid JSON body")
                self._send_error(400, "Invalid JSON")

        elif path.startswith("/admin/tokens/") and self.command == "DELETE":
            # Remove a token (by token value in path)
            token_to_remove = path.split("/")[-1]
            log.debug("Admin delete token: attempting removal")
            if remove_token(token_to_remove):
                log.info("Admin deleted token successfully")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Token removed"}).encode())
            else:
                self._send_error(404, "Token not found")

        elif path == "/admin/health":
            log.debug("Admin health check: proxy_url=%s, token_count=%d", PROXY_URL, len(_tokens))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "proxy_url": PROXY_URL,
                "token_count": len(_tokens)
            }).encode())

        else:
            log.debug("Admin: unknown endpoint %s %s", self.command, path)
            self._send_error(404, "Unknown admin endpoint")

    def _handle_proxy(self):
        """Proxy the request to the backend after validating token."""
        # Extract Bearer token
        auth_header = self.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            log.debug("Proxy: missing or malformed Authorization header")
            self._send_error(401, "Missing or invalid Authorization header. Use: Bearer <token>")
            return

        token = auth_header[7:]  # Remove "Bearer " prefix
        log.debug("Proxy: validating bearer token (%d chars)", len(token))
        token_name = validate_token(token)

        if token_name is None:
            log.info("Proxy: rejected invalid token for %s %s", self.command, self.path)
            self._send_error(403, "Invalid token")
            return

        # Token is valid - proxy the request
        target_url = f"{PROXY_URL}{self.path}"
        log.info("[AUTH OK] %s -> %s %s", token_name, self.command, self.path)

        # Forward headers (excluding Host and Authorization)
        headers = {}
        for key, value in self.headers.items():
            if key.lower() not in ("host", "authorization"):
                headers[key] = value
        log.debug("Proxy: forwarding %d headers to %s", len(headers), target_url)
        log.debug("Proxy: forwarded headers: %s", list(headers.keys()))

        try:
            # Read request body if present
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > MAX_PROXY_BODY:
                log.warning("Proxy: body too large (%d > %d)", content_length, MAX_PROXY_BODY)
                self._send_error(413, "Request body too large")
                return
            body = self.rfile.read(content_length) if content_length > 0 else None
            log.debug("Proxy: request body size=%d", content_length)

            # Make the proxied request
            log.debug("Proxy: sending %s %s (timeout=60s)", self.command, target_url)
            response = requests.request(
                method=self.command,
                url=target_url,
                headers=headers,
                data=body,
                timeout=60,
                allow_redirects=False
            )

            # Send response back to client
            log.debug("Proxy: upstream responded %d (%d bytes)", response.status_code, len(response.content))
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key.lower() not in ("transfer-encoding", "content-encoding"):
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)
            log.debug("Proxy: response forwarded to client")

        except requests.exceptions.RequestException as e:
            log.error("[PROXY ERROR] %s %s: %s", self.command, self.path, e, exc_info=DEBUG_MODE)
            self._send_error(502, "Bad Gateway: upstream service unavailable")

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
    log.info("Starting Auth Gateway...")
    log.info("Proxy target: %s", PROXY_URL)
    log.info("Tokens file: %s", TOKENS_FILE)
    log.info("Listening on port: %d", LISTEN_PORT)
    log.info("Debug mode: %s", "ON" if DEBUG_MODE else "OFF")

    if ADMIN_TOKEN:
        log.info("Admin endpoints protected with ADMIN_TOKEN")
    else:
        log.warning("Admin endpoints are unprotected! Set ADMIN_TOKEN env var for production.")

    # Load existing tokens
    load_tokens()

    # Start server
    server = HTTPServer(("0.0.0.0", LISTEN_PORT), AuthProxyHandler)
    log.info("Auth Gateway ready on port %d", LISTEN_PORT)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down...")
        server.shutdown()


if __name__ == "__main__":
    main()
