"""
AegisAI — Benchmark Ground-Truth Vulnerability Catalogs
========================================================
Defines verified ground-truth vulnerability datasets for benchmark evaluation:
  1. OWASP Juice Shop testbed
  2. OWASP crAPI testbed
  3. Custom ground-truth authorization testbed (10 verified access control bugs)
"""

from __future__ import annotations

from typing import Any

JUICE_SHOP_GROUND_TRUTH: list[dict[str, Any]] = [
    {
        "id": "JS-VULN-01",
        "title": "SQL Injection in Product Search",
        "cwe_id": "CWE-89",
        "vulnerability_type": "SQLI",
        "endpoint": "/rest/products/search",
        "method": "GET",
        "parameter": "q",
        "severity": "CRITICAL",
    },
    {
        "id": "JS-VULN-02",
        "title": "BOLA / IDOR in User Basket Access",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/rest/basket/{id}",
        "method": "GET",
        "parameter": "id",
        "severity": "HIGH",
    },
    {
        "id": "JS-VULN-03",
        "title": "Reflected XSS in Search Query",
        "cwe_id": "CWE-79",
        "vulnerability_type": "XSS",
        "endpoint": "/#/search",
        "method": "GET",
        "parameter": "q",
        "severity": "MEDIUM",
    },
    {
        "id": "JS-VULN-04",
        "title": "Improper Authentication / Admin Registration Bypass",
        "cwe_id": "CWE-306",
        "vulnerability_type": "AUTH_BYPASS",
        "endpoint": "/api/Users",
        "method": "POST",
        "parameter": "role",
        "severity": "CRITICAL",
    },
    {
        "id": "JS-VULN-05",
        "title": "Sensitive Information Exposure via Directory Listing",
        "cwe_id": "CWE-200",
        "vulnerability_type": "INFO_LEAK",
        "endpoint": "/ftp",
        "method": "GET",
        "severity": "LOW",
    },
]

CRAPI_GROUND_TRUTH: list[dict[str, Any]] = [
    {
        "id": "CRAPI-VULN-01",
        "title": "BOLA in Vehicle Location Data",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/identity/api/auth/v1/user/profile",
        "method": "GET",
        "severity": "HIGH",
    },
    {
        "id": "CRAPI-VULN-02",
        "title": "Broken Authentication in Password Reset OTP",
        "cwe_id": "CWE-307",
        "vulnerability_type": "AUTH_BYPASS",
        "endpoint": "/identity/api/auth/v1/check-otp",
        "method": "POST",
        "severity": "CRITICAL",
    },
    {
        "id": "CRAPI-VULN-03",
        "title": "BOLA in Mechanic Service Report",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/workshop/api/merchant/contact_mechanic",
        "method": "POST",
        "severity": "HIGH",
    },
    {
        "id": "CRAPI-VULN-04",
        "title": "Mass Assignment in Order Return",
        "cwe_id": "CWE-915",
        "vulnerability_type": "MASS_ASSIGNMENT",
        "endpoint": "/workshop/api/shop/orders",
        "method": "PUT",
        "severity": "HIGH",
    },
]

CUSTOM_AUTH_GROUND_TRUTH: list[dict[str, Any]] = [
    {
        "id": "AUTH-GT-01",
        "title": "BOLA in User Billing Records",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/api/v1/users/{user_id}/billing",
        "method": "GET",
        "parameter": "user_id",
        "severity": "HIGH",
    },
    {
        "id": "AUTH-GT-02",
        "title": "BOLA in Document Management",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/api/v1/documents/{doc_id}",
        "method": "GET",
        "parameter": "doc_id",
        "severity": "HIGH",
    },
    {
        "id": "AUTH-GT-03",
        "title": "IDOR in Direct Message Viewing",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/api/v1/messages/{message_id}",
        "method": "GET",
        "parameter": "message_id",
        "severity": "HIGH",
    },
    {
        "id": "AUTH-GT-04",
        "title": "Vertical Privilege Escalation in Role Assignment",
        "cwe_id": "CWE-269",
        "vulnerability_type": "AUTH_BYPASS",
        "endpoint": "/api/v1/admin/roles",
        "method": "POST",
        "severity": "CRITICAL",
    },
    {
        "id": "AUTH-GT-05",
        "title": "Missing Function-Level Access Control on System Backup",
        "cwe_id": "CWE-285",
        "vulnerability_type": "AUTH_BYPASS",
        "endpoint": "/api/v1/system/backup",
        "method": "GET",
        "severity": "CRITICAL",
    },
    {
        "id": "AUTH-GT-06",
        "title": "Cross-Tenant Data Exposure in Analytics Endpoint",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/api/v1/tenants/{tenant_id}/analytics",
        "method": "GET",
        "parameter": "tenant_id",
        "severity": "HIGH",
    },
    {
        "id": "AUTH-GT-07",
        "title": "Insecure Direct Object Reference in Order Receipts",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/api/v1/orders/{order_id}/receipt",
        "method": "GET",
        "parameter": "order_id",
        "severity": "HIGH",
    },
    {
        "id": "AUTH-GT-08",
        "title": "Unenforced Token Revocation on Session Invalidation",
        "cwe_id": "CWE-613",
        "vulnerability_type": "BROKEN_AUTH",
        "endpoint": "/api/v1/auth/refresh",
        "method": "POST",
        "severity": "MEDIUM",
    },
    {
        "id": "AUTH-GT-09",
        "title": "Cross-Tenant API Key Usage and Access",
        "cwe_id": "CWE-639",
        "vulnerability_type": "BOLA",
        "endpoint": "/api/v1/api-keys/{key_id}",
        "method": "GET",
        "parameter": "key_id",
        "severity": "HIGH",
    },
    {
        "id": "AUTH-GT-10",
        "title": "Broken Object Property Level Authorization on Profile Edit",
        "cwe_id": "CWE-284",
        "vulnerability_type": "BOLA",
        "endpoint": "/api/v1/users/{user_id}/profile",
        "method": "PUT",
        "parameter": "is_admin",
        "severity": "HIGH",
    },
]


def get_ground_truth_catalog(testbed_name: str) -> list[dict[str, Any]]:
    """Retrieve ground truth dataset for the specified testbed."""
    key = testbed_name.lower()
    if "juice" in key:
        return JUICE_SHOP_GROUND_TRUTH
    elif "crapi" in key:
        return CRAPI_GROUND_TRUTH
    elif "custom" in key or "auth" in key:
        return CUSTOM_AUTH_GROUND_TRUTH
    else:
        return JUICE_SHOP_GROUND_TRUTH + CUSTOM_AUTH_GROUND_TRUTH
