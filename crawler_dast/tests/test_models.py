"""
Unit tests for DAST data contracts and Pydantic models.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from models import (
    AuthMetadata,
    DASTReconOutput,
    DiscoveredAPI,
    DiscoveredForm,
    DiscoveredParameter,
    DiscoveredRoute,
    TargetInfo,
    TestSpecification,
    VerificationResult,
    VerificationStatus,
)


def test_dast_recon_output_contract():
    output = DASTReconOutput(
        scan_id="scan-001",
        target=TargetInfo(base_url="http://localhost:3000", is_reachable=True),
        routes=[
            DiscoveredRoute(
                path="/#/search",
                full_url="http://localhost:3000/#/search",
                is_spa_route=True,
            )
        ],
        apis=[
            DiscoveredAPI(
                url="http://localhost:3000/rest/products/search",
                method="GET",
                query_params={"q": "apple"},
                response_status=200,
            )
        ],
        forms=[
            DiscoveredForm(
                action_url="http://localhost:3000/api/login",
                method="POST",
                page_url="http://localhost:3000/#/login",
                inputs=[{"name": "email", "type": "text"}],
            )
        ],
        parameters=[
            DiscoveredParameter(
                name="q",
                location="query",
                endpoint_url="http://localhost:3000/rest/products/search",
            )
        ],
        authentication=AuthMetadata(has_jwt=True, jwt_subject="admin"),
    )

    assert output.scan_id == "scan-001"
    assert len(output.routes) == 1
    assert output.routes[0].is_spa_route is True

    # Check conversion to backend EndpointSchema
    endpoint_schemas = output.to_endpoint_schemas()
    assert len(endpoint_schemas) == 1
    assert endpoint_schemas[0]["url"] == "http://localhost:3000/rest/products/search"
    assert endpoint_schemas[0]["method"] == "GET"

    # Check AI context dictionary
    ai_context = output.to_ai_context()
    assert ai_context["total_routes"] == 1
    assert ai_context["total_apis"] == 1
    assert ai_context["authenticated"] is True


def test_test_specification_and_verification_result():
    spec = TestSpecification(
        scan_id="scan-001",
        vulnerability_type="SQLI",
        target_url="http://localhost:3000/rest/products/search",
        payload="' OR 1=1--",
    )
    assert spec.test_id.startswith("TEST-")
    assert spec.method == "GET"

    result = VerificationResult(
        test_id=spec.test_id,
        scan_id=spec.scan_id,
        vulnerability_type="SQLI",
        status=VerificationStatus.VERIFIED,
        confidence=0.95,
        is_confirmed=True,
        reason="SQL syntax error confirmed.",
    )
    assert result.is_confirmed is True

    vuln_dict = result.to_detected_vulnerability()
    assert vuln_dict is not None
    assert vuln_dict["severity"] == "CRITICAL"
    assert vuln_dict["confidence"] == 0.95
