# AegisAI — Custom Ground-Truth Authorization Benchmark (Live Empirical Evaluation)

**Lead:** Shahad — Dynamic Testing & Verification Lead  
**Target:** `http://localhost:8081` (FastAPI Custom Authorization Testbed)  
**Catalog:** `CUSTOM_AUTH_GROUND_TRUTH` (10 Verified Access Control Flaws)  
**Execution Mode:** `LIVE` (Real network sockets, Playwright browser crawl, HTTPX Exploit Runner, Deterministic Verifier)  
**Status:** **COMPLETE** — 10/10 Verified Authorization Bugs Detected across two independent reproducible live benchmark runs.

---

> [!CAUTION]
> **Controlled Security Research Testbed**: The application hosted under `crawler_dast/target_docker/custom_auth_testbed/` is deliberately vulnerable to authorization and access control flaws. It is strictly intended for local empirical benchmark evaluation and offline DAST algorithm verification. It is bound to `127.0.0.1` and must NEVER be exposed to untrusted or public networks.

---

## 1. Objective

This benchmark fulfills the primary Phase 4 requirement from Shahad's Dynamic Testing & Verification Lead roadmap:
> *"Custom ground-truth repository with 10 verified authorization bugs."*

Prior iterations utilized an in-memory synthetic simulation (`run_sample_benchmark()`). This implementation replaces that simulation with an autonomous, real-network dynamic testing benchmark executing against a live application over HTTP, with genuine Playwright reconnaissance, dual-session token management, probe generation, and deterministic verification.

---

## 2. Testbed Architecture

The testbed is implemented in `crawler_dast/target_docker/custom_auth_testbed/app.py` using Python 3.11 and FastAPI:
- **Host / Port:** `http://127.0.0.1:8081`
- **Data Persistence:** In-memory deterministic dictionary stores isolating tenants, billing records, documents, messages, orders, API keys, and profiles.
- **Seeded Principals:**
  - **User A (Attacker):** `user_id = 1001`, `tenant_id = "tenant-a"`, email: `user_a@test.local`, password: `user_a_password`, role: `user`
  - **User B (Victim):** `user_id = 1002`, `tenant_id = "tenant-b"`, email: `user_b@test.local`, password: `user_b_password`, role: `user`
  - **Admin:** `user_id = 1000`, `tenant_id = "tenant-admin"`, email: `admin@test.local`, password: `admin_password`, role: `admin`
- **Crawler Web Surface:**
  - `GET /`: Landing page with navigation links to auth, dashboard, documentation, and status
  - `GET /login`: HTML login form with `<form id="loginForm">` for Playwright DOM form extraction
  - `GET /dashboard`: Authenticated resource navigation hub
  - `GET /api/v1/public/status`: Public status endpoint

---

## 3. Docker & Deployment Setup

Containerization assets are located in `crawler_dast/target_docker/custom_auth_testbed/`:
- **`Dockerfile`**: Builds a minimal Python 3.11 slim image running `uvicorn app:app --host 0.0.0.0 --port 8081`.
- **`docker-compose.yml`**: Standalone composition exposing port `8081:8081` with HTTP healthcheck probes.
- **`requirements.txt`**: Declares `fastapi`, `uvicorn`, and `pydantic`.
- **Local Fallback / Hybrid Execution**: The benchmark harness (`benchmark_harness.py`) incorporates an auto-spawning process supervisor that starts the local uvicorn testbed if an active container is not detected on port 8081, ensuring full test reproducibility even in non-Docker environments.

---

## 4. The 10 Ground-Truth Authorization Vulnerabilities

| ID | Title | Endpoint | Method | CWE | Classification | Description |
|---|---|---|---|---|---|---|
| **AUTH-GT-01** | BOLA in User Billing Records | `/api/v1/users/{user_id}/billing` | GET | CWE-639 | BOLA / IDOR | User A requests User B's (`1002`) billing data; server leaks balance, card digits, and account numbers without ownership validation. |
| **AUTH-GT-02** | BOLA in Document Management | `/api/v1/documents/{doc_id}` | GET | CWE-639 | BOLA / IDOR | User A retrieves User B's private audit file (`doc_1002`); leaks document secret and financial details. |
| **AUTH-GT-03** | IDOR in Direct Message Viewing | `/api/v1/messages/{message_id}` | GET | CWE-639 | BOLA / IDOR | User A requests message `1002` sent by HR to User B; endpoint displays executive board review text. |
| **AUTH-GT-04** | Vertical Privilege Escalation | `/api/v1/admin/roles` | POST | CWE-269 | AUTH_BYPASS | Non-admin User A submits role change for user 1001 to `admin`; endpoint updates role without verifying admin privileges. |
| **AUTH-GT-05** | Missing Function-Level Access Control | `/api/v1/system/backup` | GET | CWE-285 | AUTH_BYPASS | Non-admin authenticated user requests system backup; endpoint returns database backup archive key and download metadata. |
| **AUTH-GT-06** | Cross-Tenant Data Exposure | `/api/v1/tenants/{tenant_id}/analytics` | GET | CWE-639 | BOLA / Cross-Tenant | User A (`tenant-a`) requests analytics for `tenant-b`; endpoint leaks revenue and internal profit metrics across tenant boundary. |
| **AUTH-GT-07** | Insecure Direct Object Reference | `/api/v1/orders/{order_id}/receipt` | GET | CWE-639 | BOLA / IDOR | User A queries receipt for order `1002`; endpoint leaks hardware receipt tokens and total expenditure of User B. |
| **AUTH-GT-08** | Unenforced Token Revocation | `/api/v1/auth/refresh` | POST | CWE-613 | BROKEN_AUTH | User refreshes session with a previously revoked refresh token; endpoint fails to query revocation blocklist and issues active session. |
| **AUTH-GT-09** | Cross-Tenant API Key Usage and Access | `/api/v1/api-keys/{key_id}` | GET | CWE-639 | BOLA / IDOR | User A requests metadata for `key_1002`; endpoint reveals User B's production API key secret `ak_live_victim_b_secret_9944`. |
| **AUTH-GT-10** | Broken Property Level Authorization | `/api/v1/users/{user_id}/profile` | PUT | CWE-284 | BOLA / Property-Level | User A updates User B's profile (`1002`) and injects `is_admin=true`; endpoint modifies victim record and elevates privileges. |

---

## 5. Authentication Model & Negative Controls

### Authentication Model
1. **Dynamic Login Handshake:** Sessions authenticate via `POST /api/v1/auth/login` exchanging credentials for scoped Bearer session tokens.
2. **Dual-Session Isolation:** `TokenManager` maintains separate HTTP header contexts for `attacker` (User A), `victim` (User B), and `admin`.
3. **Secret Redaction:** All sensitive authentication tokens, cookies, and passwords are automatically redacted from logs and exported artifacts.

### Negative Controls
To prevent false-positive inflation and ensure discriminative verification, 4 negative controls are evaluated alongside the 10 vulnerabilities:
1. **Legitimate Self Access:** User A accessing User A's billing (`/api/v1/users/1001/billing`) -> 200 OK without victim identifiers -> marked as non-vulnerable / inconclusive (no cross-tenant leak).
2. **Strict Admin Endpoint Denied:** User A accessing `/api/v1/admin/audit-logs` -> returns HTTP 403 Forbidden -> verified proper denial (`FALSE_POSITIVE` label).
3. **Nonexistent Resource:** User A requesting `/api/v1/documents/nonexistent_9999` -> returns real HTTP 404 Not Found -> correctly dismissed.
4. **Public Status Route:** Unauthenticated access to `/api/v1/public/status` -> 200 OK on intentionally public endpoint -> correctly recognized as non-vulnerable.

---

## 6. Detector Execution Path & Verification Methodology

```
+-------------------------------------------------------------------------------+
|                       AegisAI Dynamic DAST Pipeline                           |
+-------------------------------------------------------------------------------+
                                        |
  [1] Target Healthcheck                v
      - HTTP GET /api/v1/health -> Verify reachability & latency (<1000ms)
                                        |
  [2] Playwright Reconnaissance Bot     v
      - Autonomous Chromium browser crawls target routes and intercepts APIs
      - Discovers: 8 Routes, 1 API, Form inputs, SPA DOM structures
                                        |
  [3] Dual-Session Token Management     v
      - Login user_a@test.local (attacker context)
      - Login user_b@test.local (victim context)
      - Login admin@test.local (admin context)
      - Ingest Authorization Bearer headers into TokenManager
                                        |
  [4] ExploitRunner HTTPX Client        v
      - Enforces strict localhost/127.0.0.1 boundaries
      - Dispatches 14 structured TestSpecifications across network
      - Captures ExploitEvidence (status, headers, body snippet, latency)
                                        |
  [5] VerificationEngine & FP Filter    v
      - BOLA Rule: Confirms victim identifiers leaked in attacker session
      - Privilege Escalation: Confirms administrative role assigned
      - Missing Function Control: Confirms backup key returned
      - Token Revocation: Confirms active token issued from revoked refresh token
      - Negative Controls: Confirms 403/404 or absence of leak
                                        |
  [6] Benchmark Scoring & Reporting     v
      - Matches confirmed findings to CUSTOM_AUTH_GROUND_TRUTH catalog
      - Calculates TP, FP, FN, TN, Precision, Recall, F1, Detection Rate
      - Saves raw machine-readable JSON artifact with execution_mode="live"
```

---

## 7. Empirical Results

### Run 1
- **Timestamp:** `2026-09-21T13:41:14.344776`
- **Artifact:** [`benchmark_custom_ground-truth_authorization_testbed_20260921_134126.json`](file:///c:/Users/DELL/Desktop/PDS/AegisAi/crawler_dast/benchmarks/results/benchmark_custom_ground-truth_authorization_testbed_20260921_134126.json)
- **Duration:** `12.02s` (Crawl: 6.96s, Verification: 0.44s)
- **Routes Discovered:** `8`
- **APIs Intercepted:** `1`
- **Tests Executed:** `14`

| Metric | Value |
|---|---:|
| **Ground Truth Vulnerabilities** | 10 |
| **Detected Vulnerabilities** | 10 |
| **True Positives (TP)** | 10 |
| **False Positives (FP)** | 0 |
| **False Negatives (FN)** | 0 |
| **Errors Encountered** | 0 |
| **Precision** | 100.00% |
| **Recall** | 100.00% |
| **F1 Score** | 100.00% |
| **Detection Rate** | 100.00% |
| **False Positive Rate** | 0.00% |

### Run 2 (Reproducibility Validation)
- **Timestamp:** `2026-09-21T13:41:41.109256`
- **Artifact:** [`benchmark_custom_ground-truth_authorization_testbed_20260921_134152.json`](file:///c:/Users/DELL/Desktop/PDS/AegisAi/crawler_dast/benchmarks/results/benchmark_custom_ground-truth_authorization_testbed_20260921_134152.json)
- **Duration:** `11.64s` (Crawl: 7.02s, Verification: 0.44s)
- **Routes Discovered:** `8`
- **APIs Intercepted:** `1`
- **Tests Executed:** `14`

| Metric | Value |
|---|---:|
| **Ground Truth Vulnerabilities** | 10 |
| **Detected Vulnerabilities** | 10 |
| **True Positives (TP)** | 10 |
| **False Positives (FP)** | 0 |
| **False Negatives (FN)** | 0 |
| **Errors Encountered** | 0 |
| **Precision** | 100.00% |
| **Recall** | 100.00% |
| **F1 Score** | 100.00% |
| **Detection Rate** | 100.00% |
| **False Positive Rate** | 0.00% |

---

## 8. Reproducibility Comparison

```
+-----------------------------------+--------------------+--------------------+--------------------+
| Metric                            | Run 1              | Run 2              | Variance           |
+-----------------------------------+--------------------+--------------------+--------------------+
| Execution Mode                    | LIVE               | LIVE               | Identical          |
| Total Ground Truth                | 10                 | 10                 | 0                  |
| Detected Vulnerabilities          | 10                 | 10                 | 0                  |
| True Positives (TP)               | 10                 | 10                 | 0                  |
| False Positives (FP)              | 0                  | 0                  | 0                  |
| False Negatives (FN)              | 0                  | 0                  | 0                  |
| Precision                         | 100.00%            | 100.00%            | 0.00%              |
| Recall                            | 100.00%            | 100.00%            | 0.00%              |
| F1 Score                          | 100.00%            | 100.00%            | 0.00%              |
| Total Scan Duration               | 12.02s             | 11.64s             | -0.38s (-3.1%)     |
| Crawl Latency                     | 6.96s              | 7.02s              | +0.06s (+0.8%)     |
| Verification Latency              | 0.44s              | 0.44s              | 0.00s (0.0%)       |
+-----------------------------------+--------------------+--------------------+--------------------+
```

All 10 ground-truth vulnerabilities (`AUTH-GT-01` through `AUTH-GT-10`) were deterministically verified on both runs with 0 false positives and 0 false negatives.

---

## 9. Regression Testing & Compatibility

1. **Pytest Suite (`crawler_dast/tests`):**
   - **Passed:** `44 / 44` tests (100% passing rate).
   - Includes 30 existing baseline tests plus 14 new custom authorization tests.
   - Zero test regressions.
2. **Sample Mode Compatibility:**
   - Command: `python crawler_dast/benchmarks/benchmark_harness.py --sample`
   - Preserved and explicitly marked as `execution_mode: "sample"`.
3. **OWASP Juice Shop Baseline:**
   - Defined Phase 4 benchmark detection: `5 / 5` (`JS-VULN-01` to `JS-VULN-05`).
   - Ground truth catalog preserved and passing all regression assertions.
4. **OWASP crAPI v1.1.6 Baseline:**
   - Defined Phase 4C benchmark detection: `4 / 4` (`CRAPI-VULN-01-V116` to `CRAPI-VULN-04-V116`).
   - Catalog and verification harness preserved and passing all regression assertions.

---

## 10. CLI Execution Commands

To execute the live custom benchmark:
```powershell
.\venv\Scripts\python.exe crawler_dast/benchmarks/benchmark_harness.py --custom-auth-live
```

To execute the unit and integration test suite:
```powershell
.\venv\Scripts\python.exe -m pytest crawler_dast/tests -v
```

To run the legacy sample benchmark simulation:
```powershell
.\venv\Scripts\python.exe crawler_dast/benchmarks/benchmark_harness.py --sample
```
