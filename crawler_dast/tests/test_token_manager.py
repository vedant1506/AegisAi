"""
Unit tests for TokenManager: JWT parsing, multi-session management, and secret redaction.
"""

import base64
import json
import sys
from pathlib import Path

import pytest

# Ensure crawler_dast/src is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from token_manager import TokenManager, redact_secret


def make_test_jwt(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = "fake_signature_for_test"
    return f"{h_b64}.{p_b64}.{sig}"


def test_jwt_ingestion_and_decoding():
    tm = TokenManager()
    jwt_str = make_test_jwt({"sub": "admin@juice-sh.op", "role": "admin", "exp": 9999999999})
    headers = {"Authorization": f"Bearer {jwt_str}"}

    tm.ingest_from_headers(headers, session_name="default")

    assert tm.get_jwt("default") == jwt_str
    summary = tm.get_bundle_summary("default")
    assert summary["has_jwt"] is True
    assert summary["jwt_subject"] == "admin@juice-sh.op"
    assert summary["jwt_roles"] == "admin"
    assert summary["jwt_expired"] is False


def test_secret_redaction_security():
    secret_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.super_secret_payload.signature"
    redacted = redact_secret(secret_token)

    assert "super_secret_payload" not in redacted
    assert "REDACTED" in redacted
    assert redact_secret(None) == "<none>"
    assert redact_secret("short") == "***REDACTED***"


def test_multi_session_management():
    tm = TokenManager()
    jwt_attacker = make_test_jwt({"sub": "attacker@test.com", "role": "user"})
    jwt_victim = make_test_jwt({"sub": "victim@test.com", "role": "victim"})

    tm.ingest_from_headers({"Authorization": f"Bearer {jwt_attacker}"}, session_name="attacker")
    tm.ingest_from_headers({"Authorization": f"Bearer {jwt_victim}"}, session_name="victim")

    assert tm.get_jwt("attacker") == jwt_attacker
    assert tm.get_jwt("victim") == jwt_victim

    attacker_headers = tm.build_auth_headers("attacker")
    assert attacker_headers["Authorization"] == f"Bearer {jwt_attacker}"

    victim_headers = tm.build_auth_headers("victim")
    assert victim_headers["Authorization"] == f"Bearer {jwt_victim}"


def test_cookie_and_api_key_ingestion():
    tm = TokenManager()
    headers = {
        "x-api-key": "test-api-key-123",
        "x-csrf-token": "csrf-token-abc",
        "cookie": "connect.sid=session-cookie-val; other=123",
    }

    tm.ingest_from_headers(headers, session_name="default")

    assert tm.get_api_key() == "test-api-key-123"
    assert tm.get_csrf_token() == "csrf-token-abc"
    assert tm.get_session_cookie() == "session-cookie-val"

    built_headers = tm.build_auth_headers()
    assert built_headers["X-API-Key"] == "test-api-key-123"
    assert built_headers["X-CSRF-Token"] == "csrf-token-abc"
    assert "connect.sid=session-cookie-val" in built_headers["Cookie"]


def test_local_storage_ingestion():
    tm = TokenManager()
    jwt_str = make_test_jwt({"sub": "user123"})
    local_storage = {
        "token": jwt_str,
        "theme": "dark",
    }

    tm.ingest_from_local_storage(local_storage, session_name="default")
    assert tm.get_jwt() == jwt_str
