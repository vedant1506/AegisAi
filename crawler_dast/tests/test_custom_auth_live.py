"""
AegisAI — Test Suite for Custom 10-Bug Authorization Testbed
=============================================================
Validates:
  1. Testbed health and authentication
  2. All 10 ground-truth authorization vulnerabilities (AUTH-GT-01 to AUTH-GT-10)
  3. Negative controls (properly rejected requests, non-leaking endpoints, 404)
  4. Ground-truth catalog alignment and benchmark evaluation metrics
"""

from __future__ import annotations

import sys
from pathlib import Path
import pytest
import httpx

# Ensure paths
TESTS_DIR = Path(__file__).resolve().parent
SRC_DIR = TESTS_DIR.parent / "src"
BENCHMARK_DIR = TESTS_DIR.parent / "benchmarks"
TESTBED_DIR = TESTS_DIR.parent / "target_docker" / "custom_auth_testbed"

for p in (SRC_DIR, BENCHMARK_DIR, TESTBED_DIR):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app import app, SEEDED_USERS
from ground_truth_testbed import CUSTOM_AUTH_GROUND_TRUTH, get_ground_truth_catalog
from benchmark_harness import BenchmarkHarness, BenchmarkMetrics
from models import VerificationResult, VerificationStatus, ExploitEvidence


@pytest.fixture
def test_client():
    from starlette.testclient import TestClient
    return TestClient(app)


def test_testbed_health(test_client):
    """Test health and public status endpoints."""
    r = test_client.get("/api/v1/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "online"
    assert data["ground_truth_vulnerabilities"] == 10

    r_status = test_client.get("/api/v1/public/status")
    assert r_status.status_code == 200


def test_auth_login(test_client):
    """Test authentication for User A, User B, and Admin."""
    r_a = test_client.post(
        "/api/v1/auth/login",
        json={"email": "user_a@test.local", "password": "user_a_password"},
    )
    assert r_a.status_code == 200
    assert "token" in r_a.json()
    assert r_a.json()["user_id"] == 1001

    r_b = test_client.post(
        "/api/v1/auth/login",
        json={"email": "user_b@test.local", "password": "user_b_password"},
    )
    assert r_b.status_code == 200
    assert r_b.json()["user_id"] == 1002

    r_invalid = test_client.post(
        "/api/v1/auth/login",
        json={"email": "user_a@test.local", "password": "wrong_password"},
    )
    assert r_invalid.status_code == 401


def test_auth_gt_01_bola_billing(test_client):
    """AUTH-GT-01: User A requests User B's billing records."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.get("/api/v1/users/1002/billing", headers=headers_a)
    assert r.status_code == 200
    data = r.json()
    assert data["user_id"] == 1002
    assert "ACC-VICTIM-B-9921" in data["account_number"]
    assert data["balance"] == 899.00


def test_auth_gt_02_bola_document(test_client):
    """AUTH-GT-02: User A retrieves User B's confidential document."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.get("/api/v1/documents/doc_1002", headers=headers_a)
    assert r.status_code == 200
    data = r.json()
    assert data["doc_id"] == "doc_1002"
    assert data["owner_id"] == 1002
    assert data["secret"] == "VICTIM-B-SECRET-FINANCE"


def test_auth_gt_03_bola_messages(test_client):
    """AUTH-GT-03: User A reads User B's direct message."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.get("/api/v1/messages/1002", headers=headers_a)
    assert r.status_code == 200
    data = r.json()
    assert data["recipient_id"] == 1002
    assert "Confidential victim message" in data["body"]


def test_auth_gt_04_privilege_escalation_roles(test_client):
    """AUTH-GT-04: Non-admin User A grants themselves the admin role."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.post(
        "/api/v1/admin/roles",
        json={"user_id": 1001, "role": "admin"},
        headers=headers_a,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "success"
    assert data["user_id"] == 1001
    assert data["role"] == "admin"

    # Reset role back to user for clean test isolation
    SEEDED_USERS["user_a@test.local"]["role"] = "user"


def test_auth_gt_05_function_level_access_backup(test_client):
    """AUTH-GT-05: Non-admin User A accesses protected system backup."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.get("/api/v1/system/backup", headers=headers_a)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "backup_ready"
    assert data["archive_key"] == "SYS-BACKUP-SECRET-KEY-9988"


def test_auth_gt_06_cross_tenant_analytics(test_client):
    """AUTH-GT-06: User A accesses Tenant B's analytics."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.get("/api/v1/tenants/tenant-b/analytics", headers=headers_a)
    assert r.status_code == 200
    data = r.json()
    assert data["tenant_id"] == "tenant-b"
    assert data["confidential_metric"] == "TB-PROFIT-7712"


def test_auth_gt_07_order_receipt_idor(test_client):
    """AUTH-GT-07: User A retrieves User B's order receipt."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.get("/api/v1/orders/1002/receipt", headers=headers_a)
    assert r.status_code == 200
    data = r.json()
    assert data["order_id"] == 1002
    assert data["receipt_token"] == "RCPT-VICTIM-B-4411"


def test_auth_gt_08_broken_auth_token_revocation(test_client):
    """AUTH-GT-08: Revoked refresh token continues to issue new valid tokens."""
    # Revoke token
    r_rev = test_client.post(
        "/api/v1/auth/revoke",
        json={"refresh_token": "revoked_token_123"},
    )
    assert r_rev.status_code == 200

    # Refresh with revoked token
    r_ref = test_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "revoked_token_123"},
    )
    assert r_ref.status_code == 200
    assert r_ref.json()["status"] == "success"
    assert "token" in r_ref.json()


def test_auth_gt_09_api_keys_bola(test_client):
    """AUTH-GT-09: User A retrieves User B's API key secret."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.get("/api/v1/api-keys/key_1002", headers=headers_a)
    assert r.status_code == 200
    data = r.json()
    assert data["key_id"] == "key_1002"
    assert data["secret"] == "ak_live_victim_b_secret_9944"


def test_auth_gt_10_profile_edit_bola(test_client):
    """AUTH-GT-10: User A modifies User B's profile and sets admin status."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}
    r = test_client.put(
        "/api/v1/users/1002/profile",
        json={"bio": "Overwritten by attacker", "is_admin": True},
        headers=headers_a,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["bio"] == "Overwritten by attacker"
    assert data["is_admin"] is True


def test_negative_controls(test_client):
    """Validate legitimate authorization controls and proper denials."""
    headers_a = {"Authorization": "Bearer aegis_token_user_a"}

    # 1. Legitimate access: User A accessing User A's billing -> 200 OK
    r_self = test_client.get("/api/v1/users/1001/billing", headers=headers_a)
    assert r_self.status_code == 200
    assert r_self.json()["user_id"] == 1001

    # 2. Protected admin endpoint: Non-admin User A denied access with 403
    r_admin_denied = test_client.get("/api/v1/admin/audit-logs", headers=headers_a)
    assert r_admin_denied.status_code == 403

    # 3. Admin accessing admin endpoint -> 200 OK
    headers_adm = {"Authorization": "Bearer aegis_token_admin"}
    r_admin_allowed = test_client.get("/api/v1/admin/audit-logs", headers=headers_adm)
    assert r_admin_allowed.status_code == 200

    # 4. Unauthenticated request to protected endpoint -> 401
    r_unauth = test_client.get("/api/v1/users/1001/billing")
    assert r_unauth.status_code == 401

    # 5. Nonexistent resource returns 404
    r_404 = test_client.get("/api/v1/documents/nonexistent_99999", headers=headers_a)
    assert r_404.status_code == 404


def test_ground_truth_catalog_integrity():
    """Verify CUSTOM_AUTH_GROUND_TRUTH contains exactly 10 bugs with correct IDs."""
    catalog = get_ground_truth_catalog("custom_auth")
    assert len(catalog) == 10
    ids = [item["id"] for item in catalog]
    expected_ids = [f"AUTH-GT-{i:02d}" for i in range(1, 11)]
    assert ids == expected_ids
