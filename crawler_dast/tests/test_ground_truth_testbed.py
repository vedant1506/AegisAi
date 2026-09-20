"""Unit tests for ground truth testbed catalogs and version alignment."""

import pytest
import sys
from pathlib import Path

# Ensure benchmarks directory is in sys.path
BENCHMARKS_DIR = Path(__file__).resolve().parent.parent / "benchmarks"
if str(BENCHMARKS_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS_DIR))

from ground_truth_testbed import (
    CRAPI_GROUND_TRUTH,
    CRAPI_GROUND_TRUTH_V1_1_6,
    JUICE_SHOP_GROUND_TRUTH,
    CUSTOM_AUTH_GROUND_TRUTH,
    get_ground_truth_catalog,
)


def test_legacy_crapi_ground_truth_intact():
    """Ensure original legacy CRAPI_GROUND_TRUTH catalog remains untouched."""
    assert len(CRAPI_GROUND_TRUTH) == 4
    ids = [item["id"] for item in CRAPI_GROUND_TRUTH]
    assert ids == ["CRAPI-VULN-01", "CRAPI-VULN-02", "CRAPI-VULN-03", "CRAPI-VULN-04"]
    
    # Check that legacy endpoints match original specification
    endpoints = {item["id"]: item["endpoint"] for item in CRAPI_GROUND_TRUTH}
    assert endpoints["CRAPI-VULN-01"] == "/identity/api/auth/v1/user/profile"
    assert endpoints["CRAPI-VULN-02"] == "/identity/api/auth/v1/check-otp"


def test_version_aligned_crapi_v1_1_6_catalog():
    """Ensure CRAPI_GROUND_TRUTH_V1_1_6 reflects verified live endpoints."""
    assert len(CRAPI_GROUND_TRUTH_V1_1_6) == 4
    ids = [item["id"] for item in CRAPI_GROUND_TRUTH_V1_1_6]
    assert ids == [
        "CRAPI-VULN-01-V116",
        "CRAPI-VULN-02-V116",
        "CRAPI-VULN-03-V116",
        "CRAPI-VULN-04-V116",
    ]

    endpoints = {item["id"]: item["endpoint"] for item in CRAPI_GROUND_TRUTH_V1_1_6}
    assert endpoints["CRAPI-VULN-01-V116"] == "/identity/api/v2/vehicle/{carId}/location"
    assert endpoints["CRAPI-VULN-02-V116"] == "/identity/api/auth/v2/check-otp"
    assert endpoints["CRAPI-VULN-03-V116"] == "/workshop/api/merchant/contact_mechanic"
    assert endpoints["CRAPI-VULN-04-V116"] == "/workshop/api/shop/orders/{id}"


def test_catalog_retrieval_resolution():
    """Verify get_ground_truth_catalog resolves both legacy and version-aligned catalogs."""
    legacy = get_ground_truth_catalog("crapi")
    assert legacy == CRAPI_GROUND_TRUTH

    v116 = get_ground_truth_catalog("crapi_v1_1_6")
    assert v116 == CRAPI_GROUND_TRUTH_V1_1_6

    juice = get_ground_truth_catalog("owasp_juice_shop")
    assert juice == JUICE_SHOP_GROUND_TRUTH
