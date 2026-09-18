"""
AegisAI — Auth Token & Session Manager
========================================
Manages authentication tokens, session cookies, and multi-tenant
credentials captured during Playwright crawling and authenticated flows.

Security:
  - Secrets (raw JWTs, passwords, session tokens) are REDACTED from normal logs.
  - Multi-session support enables cross-tenant (Attacker vs. Victim) BOLA/IDOR testing.
  - Generates auth headers for ExploitRunner probes.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


def redact_secret(val: str | None, show_prefix: int = 6) -> str:
    """Safely redact sensitive tokens for logging and reporting."""
    if not val:
        return "<none>"
    if len(val) <= show_prefix + 4:
        return "***REDACTED***"
    return f"{val[:show_prefix]}...[REDACTED]"


@dataclass
class TokenBundle:
    """All auth credentials captured for a single user/session."""

    jwt: str | None = None
    jwt_payload: dict[str, Any] = field(default_factory=dict)
    session_cookie: str | None = None
    api_key: str | None = None
    csrf_token: str | None = None
    raw_cookies: dict[str, str] = field(default_factory=dict)
    user_label: str = "default"

    @property
    def is_expired(self) -> bool:
        """Check if JWT claim 'exp' has passed without cryptographic verification."""
        exp = self.jwt_payload.get("exp")
        if exp is None:
            return False
        return int(time.time()) >= int(exp)


class TokenManager:
    """
    Thread-safe multi-session token store.
    Holds multiple session bundles (e.g. 'default', 'attacker', 'victim').
    """

    def __init__(self) -> None:
        self._sessions: dict[str, TokenBundle] = {
            "default": TokenBundle(user_label="default")
        }

    def _get_or_create_session(self, session_name: str) -> TokenBundle:
        if session_name not in self._sessions:
            self._sessions[session_name] = TokenBundle(user_label=session_name)
        return self._sessions[session_name]

    # ── Ingestion ─────────────────────────────────────────────

    def ingest_from_headers(
        self, headers: dict[str, str], session_name: str = "default"
    ) -> None:
        """Parse auth tokens from HTTP request/response headers."""
        bundle = self._get_or_create_session(session_name)
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Authorization: Bearer <JWT>
        auth = headers_lower.get("authorization", "")
        if auth.lower().startswith("bearer "):
            raw_jwt = auth[7:].strip()
            self._store_jwt(raw_jwt, bundle)

        # API Keys
        for key_header in ("x-api-key", "api-key", "x-auth-token"):
            if key_header in headers_lower:
                bundle.api_key = headers_lower[key_header]
                logger.debug(
                    "token.api_key_captured",
                    session=session_name,
                    header=key_header,
                )
                break

        # CSRF Tokens
        for csrf_header in ("x-csrf-token", "x-xsrf-token", "csrf-token"):
            if csrf_header in headers_lower:
                bundle.csrf_token = headers_lower[csrf_header]
                logger.debug("token.csrf_captured", session=session_name)
                break

        # Cookies
        cookie_str = headers_lower.get("cookie", "") or headers_lower.get("set-cookie", "")
        if cookie_str:
            self._parse_cookies(cookie_str, bundle)

    def ingest_from_local_storage(
        self, local_storage: dict[str, str], session_name: str = "default"
    ) -> None:
        """Extract JWT or session keys stored in browser localStorage."""
        bundle = self._get_or_create_session(session_name)
        jwt_keys = ["token", "auth_token", "authToken", "jwt", "access_token", "id_token"]
        for key in jwt_keys:
            if key in local_storage and local_storage[key]:
                self._store_jwt(local_storage[key], bundle)
                logger.debug(
                    "token.jwt_from_localstorage",
                    session=session_name,
                    key=key,
                )
                return

    def ingest_cookie_objects(
        self, cookies: list[dict[str, Any]], session_name: str = "default"
    ) -> None:
        """Ingest Playwright cookie objects from browser context."""
        bundle = self._get_or_create_session(session_name)
        for cookie in cookies:
            name = cookie.get("name", "")
            value = cookie.get("value", "")
            bundle.raw_cookies[name] = value

            if name.lower() in ("connect.sid", "sessionid", "phpsessid", "session", "token"):
                bundle.session_cookie = value
                logger.debug(
                    "token.session_cookie_captured",
                    session=session_name,
                    name=name,
                )

    async def ingest_from_page(self, page: Any, session_name: str = "default") -> None:
        """Convenience method to pull localStorage & cookies from an active Playwright page."""
        try:
            storage = await page.evaluate(
                "() => Object.assign({}, window.localStorage)"
            )
            if isinstance(storage, dict):
                self.ingest_from_local_storage(storage, session_name=session_name)
        except Exception as exc:
            logger.debug("token.local_storage_read_failed", error=str(exc))

        try:
            cookies = await page.context.cookies()
            self.ingest_cookie_objects(cookies, session_name=session_name)
        except Exception as exc:
            logger.debug("token.cookies_read_failed", error=str(exc))

    # ── Retrieval ─────────────────────────────────────────────

    def get_jwt(self, session_name: str = "default") -> str | None:
        bundle = self._sessions.get(session_name)
        return bundle.jwt if bundle else None

    def get_session_cookie(self, session_name: str = "default") -> str | None:
        bundle = self._sessions.get(session_name)
        return bundle.session_cookie if bundle else None

    def get_api_key(self, session_name: str = "default") -> str | None:
        bundle = self._sessions.get(session_name)
        return bundle.api_key if bundle else None

    def get_csrf_token(self, session_name: str = "default") -> str | None:
        bundle = self._sessions.get(session_name)
        return bundle.csrf_token if bundle else None

    def build_auth_headers(self, session_name: str = "default") -> dict[str, str]:
        """Construct authorization headers for HTTP requests."""
        bundle = self._sessions.get(session_name)
        if not bundle:
            return {}

        headers: dict[str, str] = {}
        if bundle.jwt:
            headers["Authorization"] = f"Bearer {bundle.jwt}"
        if bundle.api_key:
            headers["X-API-Key"] = bundle.api_key
        if bundle.csrf_token:
            headers["X-CSRF-Token"] = bundle.csrf_token
        if bundle.session_cookie:
            headers["Cookie"] = f"connect.sid={bundle.session_cookie}"
        elif bundle.raw_cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in bundle.raw_cookies.items())

        return headers

    def get_bundle_summary(self, session_name: str = "default") -> dict[str, Any]:
        """Return safe, sanitized metadata for logging and reports (NO raw secrets)."""
        bundle = self._sessions.get(session_name)
        if not bundle:
            return {"exists": False}

        return {
            "session": session_name,
            "has_jwt": bundle.jwt is not None,
            "jwt_preview": redact_secret(bundle.jwt),
            "jwt_subject": bundle.jwt_payload.get("sub") or bundle.jwt_payload.get("email"),
            "jwt_roles": bundle.jwt_payload.get("role") or bundle.jwt_payload.get("roles") or [],
            "jwt_expired": bundle.is_expired,
            "has_session_cookie": bundle.session_cookie is not None,
            "has_api_key": bundle.api_key is not None,
            "has_csrf_token": bundle.csrf_token is not None,
            "cookie_names": list(bundle.raw_cookies.keys()),
        }

    def list_sessions(self) -> list[str]:
        return list(self._sessions.keys())

    # ── Helpers ───────────────────────────────────────────────

    def _store_jwt(self, raw_jwt: str, bundle: TokenBundle) -> None:
        bundle.jwt = raw_jwt
        try:
            payload = self._decode_jwt_payload(raw_jwt)
            bundle.jwt_payload = payload
            logger.info(
                "token.jwt_captured",
                session=bundle.user_label,
                sub=payload.get("sub") or payload.get("email"),
                exp=payload.get("exp"),
                role=payload.get("role") or payload.get("roles"),
            )
        except Exception as exc:
            logger.warning("token.jwt_decode_failed", error=str(exc))

    @staticmethod
    def _decode_jwt_payload(token: str) -> dict[str, Any]:
        """Decode base64 JWT payload segment without cryptographic verification."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT structure: expected 3 parts, got {len(parts)}")

        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding

        decoded = base64.urlsafe_b64decode(payload_b64)
        return json.loads(decoded)

    def _parse_cookies(self, cookie_str: str, bundle: TokenBundle) -> None:
        for pair in cookie_str.split(";"):
            pair = pair.strip()
            if "=" in pair:
                name, _, value = pair.partition("=")
                clean_name = name.strip()
                clean_val = value.strip()
                bundle.raw_cookies[clean_name] = clean_val
                if clean_name.lower() in ("connect.sid", "sessionid", "phpsessid", "session"):
                    bundle.session_cookie = clean_val
