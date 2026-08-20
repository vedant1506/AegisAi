"""
AegisAI — Auth Token Manager
==============================
Centralised store for tokens captured during the Playwright crawl.

Responsibilities:
  - Parse and decode JWTs (without verification — for inspection only)
  - Store session cookies, API keys, CSRF tokens
  - Provide tokens to ExploitRunner per-request
  - Detect token expiry and trigger re-authentication

Usage:
    manager = TokenManager()
    manager.ingest_from_headers({"authorization": "Bearer eyJ..."})
    token = manager.get_jwt()
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Token container ───────────────────────────────────────────

@dataclass
class TokenBundle:
    """All auth credentials captured for a single target session."""

    jwt: str | None = None
    jwt_payload: dict[str, Any] = field(default_factory=dict)
    session_cookie: str | None = None
    api_key: str | None = None
    csrf_token: str | None = None
    # Additional raw cookies keyed by name
    raw_cookies: dict[str, str] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Return True if the JWT has expired (checked without verification)."""
        exp = self.jwt_payload.get("exp")
        if exp is None:
            return False
        return int(time.time()) >= int(exp)


# ── Token Manager ────────────────────────────────────────────

class TokenManager:
    """
    Stateful manager for authentication tokens during a DAST scan.

    Thread safety: Not thread-safe — instantiate one per scan job.
    """

    def __init__(self) -> None:
        self._bundle = TokenBundle()

    # ── Ingestion ─────────────────────────────────────────────

    def ingest_from_headers(self, headers: dict[str, str]) -> None:
        """
        Parse authentication tokens from intercepted request headers.

        Detects:
          - Authorization: Bearer <JWT>
          - X-Auth-Token: <opaque>
          - X-API-Key: <key>
          - Cookie: <key>=<value>; ...
          - X-CSRF-Token: <token>
        """
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # ── JWT / Bearer ──────────────────────────────────────
        auth = headers_lower.get("authorization", "")
        if auth.lower().startswith("bearer "):
            raw_jwt = auth[7:].strip()
            self._store_jwt(raw_jwt)

        # ── API Key ───────────────────────────────────────────
        for key_header in ("x-api-key", "api-key", "x-auth-token"):
            if key_header in headers_lower:
                self._bundle.api_key = headers_lower[key_header]
                logger.debug("token.api_key_captured", header=key_header)
                break

        # ── CSRF Token ────────────────────────────────────────
        for csrf_header in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
            if csrf_header in headers_lower:
                self._bundle.csrf_token = headers_lower[csrf_header]
                logger.debug("token.csrf_captured")
                break

        # ── Cookies ───────────────────────────────────────────
        cookie_str = headers_lower.get("cookie", "")
        if cookie_str:
            self._parse_cookies(cookie_str)

    def ingest_from_local_storage(self, local_storage: dict[str, str]) -> None:
        """
        Ingest tokens stored in localStorage (captured via Playwright evaluate).

        Typical SPA pattern: JWTs stored under keys like 'token', 'authToken'.
        """
        jwt_keys = ["token", "auth_token", "authToken", "jwt", "access_token"]
        for key in jwt_keys:
            if key in local_storage:
                self._store_jwt(local_storage[key])
                logger.debug("token.jwt_from_localstorage", key=key)
                return

    def ingest_cookie_objects(self, cookies: list[dict[str, Any]]) -> None:
        """
        Ingest Playwright cookie objects (from context.cookies()).
        """
        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            self._bundle.raw_cookies[name] = value

            # Common session cookie names
            if name.lower() in ("connect.sid", "sessionid", "phpsessid", "session"):
                self._bundle.session_cookie = value
                logger.debug("token.session_cookie_captured", name=name)

    # ── Retrieval ─────────────────────────────────────────────

    def get_jwt(self) -> str | None:
        """Return the captured JWT (raw string)."""
        return self._bundle.jwt

    def get_session_cookie(self) -> str | None:
        return self._bundle.session_cookie

    def get_api_key(self) -> str | None:
        return self._bundle.api_key

    def get_csrf_token(self) -> str | None:
        return self._bundle.csrf_token

    def build_auth_headers(self) -> dict[str, str]:
        """
        Construct a set of auth headers for injection into exploit requests.
        Merges all captured credentials.
        """
        headers: dict[str, str] = {}

        if self._bundle.jwt:
            headers["Authorization"] = f"Bearer {self._bundle.jwt}"
        if self._bundle.api_key:
            headers["X-API-Key"] = self._bundle.api_key
        if self._bundle.csrf_token:
            headers["X-CSRF-Token"] = self._bundle.csrf_token
        if self._bundle.session_cookie:
            headers["Cookie"] = f"connect.sid={self._bundle.session_cookie}"
        elif self._bundle.raw_cookies:
            cookie_str = "; ".join(
                f"{k}={v}" for k, v in self._bundle.raw_cookies.items()
            )
            headers["Cookie"] = cookie_str

        return headers

    def get_bundle_summary(self) -> dict[str, Any]:
        """Return a redacted summary of captured tokens (safe to log)."""
        return {
            "has_jwt": self._bundle.jwt is not None,
            "jwt_subject": self._bundle.jwt_payload.get("sub"),
            "jwt_roles": self._bundle.jwt_payload.get("role"),
            "jwt_expired": self._bundle.is_expired,
            "has_session_cookie": self._bundle.session_cookie is not None,
            "has_api_key": self._bundle.api_key is not None,
            "has_csrf_token": self._bundle.csrf_token is not None,
            "cookie_names": list(self._bundle.raw_cookies.keys()),
        }

    # ── Internal helpers ──────────────────────────────────────

    def _store_jwt(self, raw_jwt: str) -> None:
        """Decode JWT payload (without signature verification) and store."""
        self._bundle.jwt = raw_jwt
        try:
            payload = self._decode_jwt_payload(raw_jwt)
            self._bundle.jwt_payload = payload
            logger.info(
                "token.jwt_captured",
                sub=payload.get("sub"),
                exp=payload.get("exp"),
                role=payload.get("role"),
            )
        except Exception as exc:
            logger.warning("token.jwt_decode_failed", error=str(exc))

    @staticmethod
    def _decode_jwt_payload(token: str) -> dict[str, Any]:
        """
        Decode the JWT payload section without verifying the signature.
        Used purely for introspection — NEVER trust this for auth decisions.
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT structure: expected 3 parts, got {len(parts)}")

        payload_b64 = parts[1]
        # Add padding if required
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        decoded = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded)

    def _parse_cookies(self, cookie_str: str) -> None:
        """Parse a Cookie header string into individual name/value pairs."""
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                self._bundle.raw_cookies[name.strip()] = value.strip()
