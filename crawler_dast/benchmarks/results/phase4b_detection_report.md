# AegisAI — Phase 4B Detection Coverage Improvement Report

**Author:** Shahad — Dynamic Testing & Verification Lead  
**Target:** OWASP Juice Shop (`http://localhost:3000`)  
**Evaluation Date:** 2026-09-20  
**Status:** **PASSED — ALL 5 GROUND TRUTH VULNERABILITIES DETECTED**

---

## 1. Executive Summary

Phase 4B focused on closing the detection gaps identified in Phase 4A where three ground-truth vulnerabilities (`JS-VULN-01` SQL Injection, `JS-VULN-03` DOM Cross-Site Scripting, and `JS-VULN-04` Admin Registration Privilege Escalation) were missed, yielding a baseline Recall of 40.0% (TP=2, FN=3).

By introducing generalized multi-signal verification without hardcoding vulnerability IDs or altering core crawler architecture, AegisAI achieved **100.0% Recall (5/5 ground truth detected)** and **100.0% Precision (0 False Positives)** with **0.0% False Positive Rate (FPR)** across 9 live test probes.

---

## 2. Quantitative Metric Comparison: Phase 4A vs Phase 4B

| Evaluation Metric | Phase 4A Baseline | Phase 4B Improved | Absolute Delta | Relative Improvement |
| :--- | :---: | :---: | :---: | :---: |
| **Ground Truth Targets** | 5 | 5 | 0 | — |
| **Tests Executed** | 9 | 9 | 0 | — |
| **True Positives (TP)** | 2 | **5** | **+3** | **+150.0%** |
| **False Positives (FP)** | 0 | **0** | 0 | Maintained 0 |
| **False Negatives (FN)** | 3 | **0** | **-3** | **-100.0% (Zero Missed)** |
| **Precision** | 100.0% | **100.0%** | 0.0% | Maintained 100% |
| **Recall** | 40.0% | **100.0%** | **+60.0%** | **+150.0%** |
| **Detection Rate** | 40.0% | **100.0%** | **+60.0%** | **+150.0%** |
| **F1 Score** | 57.14% | **100.0%** | **+42.86%** | **+75.0%** |
| **False Positive Rate (FPR)** | 0.0% | **0.0%** | 0.0% | Maintained 0% |
| **Scan Execution Duration** | 8.93s | 11.39s | +2.46s | Fast execution |
| **Regression Suite Pass** | 22 Passed | **27 Passed** | **+5 tests** | 0 Regressions |

---

## 3. Empirical Diagnosis and Architectural Fixes

### 3.1. JS-VULN-01: SQL Injection (`/rest/products/search`)
- **Phase 4A Defect:** The engine only inspected HTTP responses for database syntax error regex patterns. Juice Shop uses SQLite parameterized UNION injection that succeeds with HTTP 200 OK without emitting raw database errors.
- **Phase 4B Fix:** Implemented boolean differential testing in `_verify_sqli`:
  - Compares length and structural response divergence between logical TRUE (`apple')) OR 1=1--`) and logical FALSE (`apple')) AND 1=2--`).
  - Observed live: TRUE condition returned 8,192+ bytes (56 products) vs FALSE returning 30 bytes (0 products) — a 273.1x differential ratio, confirming SQL execution.
  - Also added syntax crash detection (HTTP 500) and UNION response body expansion tracking.

### 3.2. JS-VULN-03: DOM Cross-Site Scripting (`/#/search`)
- **Phase 4A Defect:** The probe fired an HTTP GET request to `/rest/products/search`. The response header `Content-Type: application/json` prevented HTML execution, and client-side hash routing was inaccessible over raw HTTP.
- **Phase 4B Fix:** 
  - Added `_dispatch_dom_probe` to `ExploitRunner` using headless Playwright Chromium.
  - Added `dom_evidence` to `ExploitEvidence` capturing rendered DOM elements.
  - In `_verify_xss`, browser DOM inspection verified active injection of `iframe[src='javascript:alert(1)']` directly into the live Document Object Model tree with 0.95 confidence.

### 3.3. JS-VULN-04: Admin Registration Bypass (`/api/Users`)
- **Phase 4A Defect:** Static email values caused SQL unique constraint violations (`SequelizeUniqueConstraintError`) returning HTTP 400 on subsequent runs. Furthermore, `_verify_auth_bypass` did not check for role reflection in HTTP 201 Created responses.
- **Phase 4B Fix:** 
  - Dynamic run-unique identity parameterization (`bench_admin_escalate_<uuid>@test.com`) with required security questions.
  - Enhanced `_verify_auth_bypass` to detect elevated role assignments (`"role":"admin"`) in HTTP 200/201 responses.
  - Verified live: registration succeeded with HTTP 201 Created and confirmed `"role":"admin"`.

---

## 4. Ground-Truth Catalog Mapping (Phase 4B)

| Vuln ID | Title | Endpoint | Method | Ground Truth CWE | Live Status | Evidence / Reason |
| :--- | :--- | :--- | :---: | :---: | :---: | :--- |
| **JS-VULN-01** | SQL Injection | `/rest/products/search` | GET | CWE-89 | **VERIFIED** | Boolean differential (273.1x ratio, 8,162B diff) |
| **JS-VULN-02** | BOLA Basket Access | `/rest/basket/{id}` | GET | CWE-639 | **VERIFIED** | Cross-tenant IDOR confirmed (`Products`, `UserId` leaked) |
| **JS-VULN-03** | DOM XSS Search | `/#/search` | GET | CWE-79 | **VERIFIED** | Active `iframe` rendered in browser DOM tree |
| **JS-VULN-04** | Admin Reg Bypass | `/api/Users` | POST | CWE-306 | **VERIFIED** | User registered with elevated `admin` role (HTTP 201) |
| **JS-VULN-05** | Directory Listing | `/ftp` | GET | CWE-200 | **VERIFIED** | `listing directory /ftp` observed in response |

---

## 5. Negative Control Stability

| Control ID | Probe Target | Expected Result | Live Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| `BENCH-TC-06-CTRL-SOFT404` | `/api/users/9999999` | False Positive Rejection | HTTP 401 Authorization Denied | **FP Filtered** |
| `BENCH-TC-07-CTRL-STATIC` | `/assets/public/favicon.ico` | Static Asset Filter | Static asset heuristic flagged | **FP Filtered** |
| `BENCH-TC-08-CTRL-DENIED` | `/rest/user/change-password` | 401 Rejection Accepted | HTTP 401 properly enforced | **FP Filtered** |
| `BENCH-TC-09-CTRL-BENIGN` | `/rest/products/search?q=banana`| Benign Query Filter | No anomaly observed | **FP Filtered** |

---

## 6. Reproducibility & Stability Audit

A controlled two-run reproducibility audit was executed against OWASP Juice Shop with identical configuration (`max_pages=8`, `timeout=15,000ms`, `max_depth=2`):

- **Discovered Routes:** Run 1 = 8, Run 2 = 8 (Jaccard similarity: **1.0**)
- **Discovered APIs:** Run 1 = 19, Run 2 = 19 (Jaccard similarity: **1.0**)
- **Discovered Forms:** Run 1 = 3, Run 2 = 3 (Delta: **0**)
- **Discovered Parameters:** Run 1 = 16, Run 2 = 16 (Delta: **0**)
- **Wall Time Duration:** Run 1 = 8.17s, Run 2 = 8.27s (Delta: **0.10s**)
- **Audit Evidence:** Saved to `crawler_dast/benchmarks/results/reproducibility_audit.json`.

---

## 7. Artifact Integrity

- **Phase 4A Baseline (Preserved):** `crawler_dast/benchmarks/results/benchmark_owasp_juice_shop_20260920_101805.json`
- **Phase 4B Benchmark Artifact:** `crawler_dast/benchmarks/results/phase4b_detection_improvement_20260920_102917.json`
- **Scope Compliance:** Only `crawler_dast/` files were modified. No changes made to `backend/`, `frontend/`, `ai_engine/`, or repository root.
