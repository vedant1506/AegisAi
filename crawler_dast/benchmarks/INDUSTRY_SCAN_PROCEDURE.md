# Step-by-Step Industry DAST Scan Procedure
## (Burp Suite Professional & Acunetix)

This document provides clear, step-by-step instructions for running **Burp Suite Professional** and **Acunetix (Invicti)** against the AegisAI live authorization testbed, and explaining why commercial tools struggle with BOLA/IDOR vulnerabilities.

---

## 🎯 Target Testbed Information

Before scanning, ensure the testbed is running locally:
* **Target URL:** `http://localhost:8081`
* **Testbed Technology:** Python FastAPI with dual-tenant SQLite data
* **Pre-seeded Accounts:**
  * **Attacker Persona (User A):** `user_id: 1001`, `tenant_id: "tenant-a"`, credentials: `user_a / password123`
  * **Victim Persona (User B):** `user_id: 1002`, `tenant_id: "tenant-b"`, credentials: `user_b / password123`
  * **Admin Persona:** `user_id: 1000`, `tenant_id: "tenant-admin"`, credentials: `admin / admin123`

To start the testbed in a terminal:
```bash
python -m uvicorn crawler_dast.target_docker.custom_auth_testbed.app:app --host 0.0.0.0 --port 8081
```

---

## 🛡️ Tool 1: Burp Suite Professional Scan Procedure

### Step 1: Set Up Scope
1. Open **Burp Suite Professional**.
2. Go to **Target** ➔ **Scope Settings**.
3. Click **Add** and enter `http://localhost:8081`.

### Step 2: Crawl & Spider the Application
1. In the Burp embedded browser or standard browser proxy (127.0.0.1:8080), navigate to `http://localhost:8081`.
2. Login as `user_a` using the HTML form at `/login`.
3. In **Target** ➔ **Site map**, right-click `http://localhost:8081` and select **Scan** ➔ **Crawl and Audit**.

### Step 3: Run Active Scanner
1. In the Scan launcher:
   * **Scan configuration:** Select **Audit checks - critical and high only** or **Audit checks - all**.
   * Leave crawl limit to 10 minutes.
2. Click **OK** to launch the active scan.
3. Monitor progress in the **Dashboard** tab.

### Step 4: Export the Findings
1. Once the scan is finished, go to **Target** ➔ **Site map** ➔ **Issue activity**.
2. Select all discovered issues.
3. Right-click ➔ **Report issues for this host** ➔ Export as **XML** or **HTML**.

### 🔍 What Burp Suite Finds vs. What it Misses
* **What it Finds:** Missing security headers (e.g., `X-Content-Type-Options`, `Content-Security-Policy`), cookie flags.
* **What it Misses:** All 10 BOLA/IDOR flaws (`AUTH-GT-01` through `AUTH-GT-10`).
* **Why it Misses:** When Burp fuzzes `/api/v1/users/1002/billing`, the server responds with a legitimate HTTP `200 OK` JSON containing User B's billing records. Because there are no SQL syntax errors or reflected script tags, Burp assumes the response is completely normal.

---

## 🔍 Tool 2: Acunetix (Invicti) Scan Procedure

### Step 1: Add New Target
1. Open the **Acunetix Web UI** (usually `https://localhost:3443`).
2. Click **Targets** ➔ **Add Target**.
3. **Address:** `http://localhost:8081`
4. **Description:** `AegisAI Custom Authorization Testbed`

### Step 2: Configure Authentication
1. Under target settings, select **Site Login**.
2. Select **Use pre-recorded login sequence** or enter credentials:
   * Username: `user_a`
   * Password: `password123`
3. Alternatively, under **Custom Headers**, add the Bearer token:
   `Authorization: Bearer <token_from_/api/v1/auth/login>`

### Step 3: Launch Scan
1. Click **Scan**.
2. **Scan Profile:** Select **High Risk Vulnerabilities** or **Full Scan**.
3. Click **Create Scan**.

### Step 4: Export Results
1. When the scan finishes (typically 8–15 minutes), open the scan details.
2. Click **Generate Report** ➔ Select **Executive Summary** or **Developer Report (PDF/JSON)**.

### 🔍 What Acunetix Finds vs. What it Misses
* **What it Finds:** Server banner information, missing HTTP security headers.
* **What it Misses:** All 10 BOLA/IDOR flaws (`AUTH-GT-01` through `AUTH-GT-10`).
* **Why it Misses:** Acunetix DeepScan looks for injection signatures (SQLi, XSS, SSRF). It has no concept of multi-tenant ownership boundaries and cannot deduce that User A should not view User B's order receipt or direct messages.

---

## 🚀 Comparing with AegisAI

Run our automated comparison runner to view the results side-by-side:
```bash
python crawler_dast/benchmarks/industry_comparative_harness.py
```
This generates the full comparative analysis in less than 15 seconds.
