"""
AegisAI — Custom Ground-Truth Authorization Benchmark Testbed
=============================================================
A lightweight, intentionally vulnerable FastAPI application hosting:
  - 10 verified ground-truth authorization bugs (AUTH-GT-01 to AUTH-GT-10)
  - Deterministic dual-tenant and administrative seeded test data
  - Negative controls (properly rejected unauthorized requests and legitimate authorized access)
  - Web UI routes (login, dashboard, HTML forms) for crawler discovery

Port: 8081 (Default)
Host: 127.0.0.1 / 0.0.0.0
"""

from __future__ import annotations

import time
from typing import Any
from fastapi import FastAPI, Depends, HTTPException, Header, Request, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(
    title="AegisAI Custom Authorization Benchmark Testbed",
    description="Deliberately vulnerable API hosting 10 verified authorization flaws for dynamic testing.",
    version="1.0.0",
)

# ── Seeded In-Memory Database ─────────────────────────────────

SEEDED_USERS = {
    "user_a@test.local": {
        "user_id": 1001,
        "email": "user_a@test.local",
        "password": "user_a_password",
        "tenant_id": "tenant-a",
        "role": "user",
        "name": "Alice Attacker",
    },
    "user_b@test.local": {
        "user_id": 1002,
        "email": "user_b@test.local",
        "password": "user_b_password",
        "tenant_id": "tenant-b",
        "role": "user",
        "name": "Bob Victim",
    },
    "admin@test.local": {
        "user_id": 1000,
        "email": "admin@test.local",
        "password": "admin_password",
        "tenant_id": "tenant-admin",
        "role": "admin",
        "name": "System Administrator",
    },
}

# Lookup by ID
USERS_BY_ID = {u["user_id"]: u for u in SEEDED_USERS.values()}

# User Profiles
PROFILES = {
    1001: {
        "user_id": 1001,
        "name": "Alice Attacker",
        "email": "user_a@test.local",
        "bio": "Security researcher",
        "is_admin": False,
    },
    1002: {
        "user_id": 1002,
        "name": "Bob Victim",
        "email": "user_b@test.local",
        "bio": "Financial Director",
        "is_admin": False,
    },
    1000: {
        "user_id": 1000,
        "name": "System Administrator",
        "email": "admin@test.local",
        "bio": "Cluster Administrator",
        "is_admin": True,
    },
}

# Billing Records
BILLING_RECORDS = {
    1001: {
        "user_id": 1001,
        "tenant_id": "tenant-a",
        "account_number": "ACC-ALICE-A-1100",
        "plan": "Standard Tier",
        "balance": 149.99,
        "card_last4": "1111",
        "billing_cycle": "monthly",
    },
    1002: {
        "user_id": 1002,
        "tenant_id": "tenant-b",
        "account_number": "ACC-VICTIM-B-9921",
        "plan": "Enterprise Corporate",
        "balance": 899.00,
        "card_last4": "4242",
        "billing_cycle": "annual",
    },
}

# Documents
DOCUMENTS = {
    "doc_1001": {
        "doc_id": "doc_1001",
        "owner_id": 1001,
        "tenant_id": "tenant-a",
        "title": "Alice Public Strategic Plan",
        "content": "Roadmap for tenant A Q4.",
        "secret": "ALICE-DOC-SECRET-01",
    },
    "doc_1002": {
        "doc_id": "doc_1002",
        "owner_id": 1002,
        "tenant_id": "tenant-b",
        "title": "User B Secret Financial Audit",
        "content": "Confidential audit details and balance sheet for tenant B.",
        "secret": "VICTIM-B-SECRET-FINANCE",
    },
}

# Messages
MESSAGES = {
    1001: {
        "message_id": 1001,
        "sender": "Operations",
        "recipient_id": 1001,
        "subject": "System Welcome",
        "body": "Welcome Alice to tenant A.",
    },
    1002: {
        "message_id": 1002,
        "sender": "HR Executive",
        "recipient_id": 1002,
        "subject": "Confidential Board Review",
        "body": "Confidential victim message to board regarding annual merger.",
    },
}

# Tenant Analytics
TENANT_ANALYTICS = {
    "tenant-a": {
        "tenant_id": "tenant-a",
        "active_users": 12,
        "total_revenue": 52000,
        "confidential_metric": "TA-METRIC-1001",
    },
    "tenant-b": {
        "tenant_id": "tenant-b",
        "active_users": 140,
        "total_revenue": 145000,
        "confidential_metric": "TB-PROFIT-7712",
    },
}

# Orders
ORDERS = {
    1001: {
        "order_id": 1001,
        "owner_id": 1001,
        "item": "Standard Support Package",
        "amount": 150.00,
        "receipt_token": "RCPT-ALICE-A-0001",
    },
    1002: {
        "order_id": 1002,
        "owner_id": 1002,
        "item": "Victim B Hardware Order",
        "amount": 2499.00,
        "receipt_token": "RCPT-VICTIM-B-4411",
    },
}

# API Keys
API_KEYS = {
    "key_1001": {
        "key_id": "key_1001",
        "owner_id": 1001,
        "tenant_id": "tenant-a",
        "name": "Alice Integration Key",
        "secret": "ak_live_alice_key_112233",
        "status": "active",
    },
    "key_1002": {
        "key_id": "key_1002",
        "owner_id": 1002,
        "tenant_id": "tenant-b",
        "name": "Victim B Production Master Key",
        "secret": "ak_live_victim_b_secret_9944",
        "status": "active",
    },
}

# Token Tracking & Revocation Store
REVOKED_TOKENS: set[str] = set()
ACTIVE_SESSIONS: dict[str, dict[str, Any]] = {}


# ── Authentication Helper & Dependency ────────────────────────

def create_session_token(user: dict[str, Any]) -> tuple[str, str]:
    token = f"aegis_token_{user['user_id']}_{int(time.time())}"
    refresh_token = f"aegis_refresh_{user['user_id']}_{int(time.time())}"
    ACTIVE_SESSIONS[token] = user
    return token, refresh_token


def get_current_user(authorization: str | None = Header(None)) -> dict[str, Any]:
    """Validate Bearer token and return current authenticated user object."""
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
        )
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization scheme. Use 'Bearer <token>'",
        )
    token = parts[1]
    # Check if token corresponds to active session or known deterministic test tokens
    if token in ACTIVE_SESSIONS:
        return ACTIVE_SESSIONS[token]
    
    # Deterministic fallback tokens for headless test suites
    if "1001" in token or "user_a" in token or "attacker" in token:
        return SEEDED_USERS["user_a@test.local"]
    elif "1002" in token or "user_b" in token or "victim" in token:
        return SEEDED_USERS["user_b@test.local"]
    elif "1000" in token or "admin" in token:
        return SEEDED_USERS["admin@test.local"]
    
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired Bearer token",
    )


# ── Web / Crawler Interface Routes ────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index_view():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>AegisAI Custom Authorization Testbed</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }
            a { color: #38bdf8; text-decoration: none; }
            .card { background: #1e293b; padding: 24px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #334155; }
            h1 { color: #38bdf8; }
            ul { line-height: 1.8; }
        </style>
    </head>
    <body>
        <h1>AegisAI Custom Authorization Testbed</h1>
        <p>Target application hosting 10 verified authorization vulnerabilities for DAST benchmarks.</p>
        <div class="card">
            <h2>Navigation</h2>
            <ul>
                <li><a id="nav-login" href="/login">User Login Form</a></li>
                <li><a id="nav-dashboard" href="/dashboard">User Dashboard</a></li>
                <li><a id="nav-docs" href="/docs">OpenAPI Documentation</a></li>
                <li><a id="nav-status" href="/api/v1/public/status">Service Health Status</a></li>
            </ul>
        </div>
    </body>
    </html>
    """


@app.get("/login", response_class=HTMLResponse)
async def login_view():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Testbed Login</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }
            .box { max-width: 400px; margin: 0 auto; background: #1e293b; padding: 30px; border-radius: 8px; }
            input { width: 100%; padding: 10px; margin: 8px 0 16px; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: #fff; box-sizing: border-box; }
            button { width: 100%; padding: 12px; background: #38bdf8; color: #0f172a; border: none; font-weight: bold; border-radius: 4px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="box">
            <h2>Authentication Portal</h2>
            <form id="loginForm" action="/api/v1/auth/login" method="POST">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" value="user_a@test.local" required />
                <label for="password">Password</label>
                <input type="password" id="password" name="password" value="user_a_password" required />
                <button type="submit" id="loginButton">Log In</button>
            </form>
        </div>
    </body>
    </html>
    """


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_view():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Dashboard</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; background: #0f172a; color: #f8fafc; }
            .card { background: #1e293b; padding: 20px; border-radius: 8px; margin-bottom: 16px; }
            a { color: #38bdf8; }
        </style>
    </head>
    <body>
        <h1>Enterprise Dashboard</h1>
        <div class="card">
            <h3>Active Resources</h3>
            <ul>
                <li><a href="/api/v1/users/1001/billing">My Billing Records</a></li>
                <li><a href="/api/v1/documents/doc_1001">My Documents</a></li>
                <li><a href="/api/v1/messages/1001">My Inbox</a></li>
                <li><a href="/api/v1/tenants/tenant-a/analytics">Tenant Analytics</a></li>
                <li><a href="/api/v1/orders/1001/receipt">Order Receipts</a></li>
                <li><a href="/api/v1/api-keys/key_1001">API Key Secrets</a></li>
            </ul>
        </div>
    </body>
    </html>
    """


# ── Public / Health / Status Endpoints ────────────────────────

@app.get("/api/v1/public/status")
@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "online",
        "service": "custom_auth_testbed",
        "version": "1.0.0",
        "ground_truth_vulnerabilities": 10,
        "timestamp": time.time(),
    }


# ── Authentication API ────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str

@app.post("/api/v1/auth/login")
async def login(req: LoginRequest):
    user = SEEDED_USERS.get(req.email)
    if not user or user["password"] != req.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    token, refresh_token = create_session_token(user)
    return {
        "token": token,
        "refresh_token": refresh_token,
        "user_id": user["user_id"],
        "tenant_id": user["tenant_id"],
        "role": user["role"],
        "name": user["name"],
        "status": "authenticated",
    }


class RevokeRequest(BaseModel):
    refresh_token: str

@app.post("/api/v1/auth/revoke")
async def revoke_token(req: RevokeRequest):
    REVOKED_TOKENS.add(req.refresh_token)
    return {
        "status": "revoked",
        "refresh_token": req.refresh_token,
        "message": "Token has been added to revocation blocklist.",
    }


# ── VULNERABILITY 8: AUTH-GT-08 ───────────────────────────────
# CWE-613: Broken Authentication / Token Revocation
# VULN: Fails to check REVOKED_TOKENS blocklist, allowing revoked tokens to refresh.

class RefreshRequest(BaseModel):
    refresh_token: str

@app.post("/api/v1/auth/refresh")
async def refresh_token(req: RefreshRequest):
    # Intentional flaw: DOES NOT check if req.refresh_token in REVOKED_TOKENS!
    user_id = 1002 if "1002" in req.refresh_token or "victim" in req.refresh_token else 1001
    user = USERS_BY_ID.get(user_id, SEEDED_USERS["user_b@test.local"])
    new_token, _ = create_session_token(user)
    return {
        "status": "success",
        "token": new_token,
        "user_id": user["user_id"],
        "refreshed": True,
        "message": "Session successfully renewed using refresh token.",
    }


# ── VULNERABILITY 1: AUTH-GT-01 ───────────────────────────────
# CWE-639: BOLA in User Billing Records
# VULN: Does not check current_user["user_id"] == user_id.

@app.get("/api/v1/users/{user_id}/billing")
async def get_user_billing(user_id: int, current_user: dict = Depends(get_current_user)):
    record = BILLING_RECORDS.get(user_id)
    if not record:
        raise HTTPException(status_code=404, detail="Billing record not found")
    # Intentional BOLA: Any authenticated user can view any user's billing records
    return {
        "user_id": record["user_id"],
        "account_number": record["account_number"],
        "plan": record["plan"],
        "balance": record["balance"],
        "card_last4": record["card_last4"],
        "billing_cycle": record["billing_cycle"],
        "tenant_id": record["tenant_id"],
        "status": "active",
    }


# ── VULNERABILITY 2: AUTH-GT-02 ───────────────────────────────
# CWE-639: BOLA in Document Management
# VULN: Does not check document owner.

@app.get("/api/v1/documents/{doc_id}")
async def get_document(doc_id: str, current_user: dict = Depends(get_current_user)):
    doc = DOCUMENTS.get(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    # Intentional BOLA: Any authenticated user can view another user's document
    return {
        "doc_id": doc["doc_id"],
        "owner_id": doc["owner_id"],
        "tenant_id": doc["tenant_id"],
        "title": doc["title"],
        "content": doc["content"],
        "secret": doc["secret"],
    }


# ── VULNERABILITY 3: AUTH-GT-03 ───────────────────────────────
# CWE-639: IDOR in Direct Message Viewing
# VULN: Does not check message recipient or sender.

@app.get("/api/v1/messages/{message_id}")
async def get_message(message_id: int, current_user: dict = Depends(get_current_user)):
    msg = MESSAGES.get(message_id)
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    # Intentional BOLA: Any authenticated user can read another user's direct messages
    return {
        "message_id": msg["message_id"],
        "recipient_id": msg["recipient_id"],
        "sender": msg["sender"],
        "subject": msg["subject"],
        "body": msg["body"],
    }


# ── VULNERABILITY 4: AUTH-GT-04 ───────────────────────────────
# CWE-269: Vertical Privilege Escalation in Role Assignment
# VULN: Non-admin can invoke admin role assignment endpoint.

class RoleUpdateRequest(BaseModel):
    user_id: int
    role: str

@app.post("/api/v1/admin/roles")
async def update_user_role(req: RoleUpdateRequest, current_user: dict = Depends(get_current_user)):
    # Intentional flaw: DOES NOT verify current_user["role"] == "admin"!
    target_user = USERS_BY_ID.get(req.user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")
    
    target_user["role"] = req.role
    if req.user_id in PROFILES:
        PROFILES[req.user_id]["is_admin"] = (req.role.lower() == "admin")
    
    return {
        "status": "success",
        "user_id": req.user_id,
        "role": req.role,
        "assigned_by": current_user["email"],
        "message": f"Role successfully updated to {req.role}.",
    }


# ── VULNERABILITY 5: AUTH-GT-05 ───────────────────────────────
# CWE-285: Missing Function-Level Access Control on System Backup
# VULN: Non-admin can download/inspect database backup archives.

@app.get("/api/v1/system/backup")
async def get_system_backup(current_user: dict = Depends(get_current_user)):
    # Intentional flaw: DOES NOT verify current_user["role"] == "admin"!
    return {
        "status": "backup_ready",
        "download_url": "/backups/system_db_2026.sql.gz",
        "database_size_mb": 450,
        "system_admin": "root",
        "archive_key": "SYS-BACKUP-SECRET-KEY-9988",
        "scope": "full_cluster_database_dump",
        "created_at": "2026-09-20T10:00:00Z",
    }


# ── VULNERABILITY 6: AUTH-GT-06 ───────────────────────────────
# CWE-639 / CWE-284: Cross-Tenant Data Exposure in Analytics Endpoint
# VULN: User from tenant A can access analytics belonging to tenant B.

@app.get("/api/v1/tenants/{tenant_id}/analytics")
async def get_tenant_analytics(tenant_id: str, current_user: dict = Depends(get_current_user)):
    analytics = TENANT_ANALYTICS.get(tenant_id)
    if not analytics:
        raise HTTPException(status_code=404, detail="Tenant analytics not found")
    # Intentional flaw: DOES NOT check current_user["tenant_id"] == tenant_id!
    return {
        "tenant_id": analytics["tenant_id"],
        "active_users": analytics["active_users"],
        "total_revenue": analytics["total_revenue"],
        "confidential_metric": analytics["confidential_metric"],
    }


# ── VULNERABILITY 7: AUTH-GT-07 ───────────────────────────────
# CWE-639: Insecure Direct Object Reference in Order Receipts
# VULN: User A can view User B's order receipt.

@app.get("/api/v1/orders/{order_id}/receipt")
async def get_order_receipt(order_id: int, current_user: dict = Depends(get_current_user)):
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    # Intentional flaw: DOES NOT check current_user["user_id"] == order["owner_id"]!
    return {
        "order_id": order["order_id"],
        "owner_id": order["owner_id"],
        "item": order["item"],
        "amount": order["amount"],
        "receipt_token": order["receipt_token"],
        "status": "delivered",
    }


# ── VULNERABILITY 9: AUTH-GT-09 ───────────────────────────────
# CWE-639: Cross-Tenant API Key Usage and Access
# VULN: User A can retrieve User B's API key and secret.

@app.get("/api/v1/api-keys/{key_id}")
async def get_api_key(key_id: str, current_user: dict = Depends(get_current_user)):
    key_entry = API_KEYS.get(key_id)
    if not key_entry:
        raise HTTPException(status_code=404, detail="API key not found")
    # Intentional flaw: DOES NOT check current_user["user_id"] == key_entry["owner_id"]!
    return {
        "key_id": key_entry["key_id"],
        "owner_id": key_entry["owner_id"],
        "tenant_id": key_entry["tenant_id"],
        "name": key_entry["name"],
        "secret": key_entry["secret"],
        "status": key_entry["status"],
    }


# ── VULNERABILITY 10: AUTH-GT-10 ──────────────────────────────
# CWE-284 / CWE-639: Broken Object Property Level Authorization on Profile Edit
# VULN: User A can modify User B's profile and elevate admin property.

class ProfileUpdateRequest(BaseModel):
    bio: str | None = None
    name: str | None = None
    is_admin: bool | None = None

@app.put("/api/v1/users/{user_id}/profile")
async def update_profile(
    user_id: int,
    req: ProfileUpdateRequest,
    current_user: dict = Depends(get_current_user),
):
    profile = PROFILES.get(user_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    # Intentional flaw: DOES NOT check current_user["user_id"] == user_id
    # AND allows client to assign is_admin property directly!
    if req.bio is not None:
        profile["bio"] = req.bio
    if req.name is not None:
        profile["name"] = req.name
    if req.is_admin is not None:
        profile["is_admin"] = req.is_admin

    return {
        "user_id": profile["user_id"],
        "name": profile["name"],
        "bio": profile["bio"],
        "is_admin": profile["is_admin"],
        "updated": True,
        "message": "User profile successfully updated.",
    }


# ── NEGATIVE CONTROLS (Properly Protected Endpoints) ───────────

@app.get("/api/v1/admin/audit-logs")
async def get_admin_audit_logs(current_user: dict = Depends(get_current_user)):
    """Properly protected endpoint: strictly enforces admin role."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: administrative privileges required.",
        )
    return {
        "status": "success",
        "audit_logs": [
            {"event": "login", "user": "admin", "timestamp": "2026-09-20T12:00:00Z"},
            {"event": "policy_update", "user": "admin", "timestamp": "2026-09-20T12:05:00Z"},
        ],
    }


@app.get("/api/v1/secure/vault")
async def get_secure_vault(current_user: dict = Depends(get_current_user)):
    """Properly protected endpoint: denies non-admin users."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access to system vault.",
        )
    return {"vault": "encrypted_master_key_994411"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8081, reload=False)
