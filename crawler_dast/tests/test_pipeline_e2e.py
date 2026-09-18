"""
End-to-end pipeline test using an in-process local HTTP server.
Validates the complete chain:
  Local mock target → Playwright crawler → Tokens → ExploitRunner → Verifier → FP Filter.
"""

import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from false_positive_filter import FalsePositiveFilter
from models import TestSpecification, VerificationStatus
from playwright_bot import CrawlerConfig, run_playwright_crawler
from token_manager import TokenManager
from verifier import VerificationEngine, execute_and_verify


# ── In-Process Mock Target Server ─────────────────────────────

class MockTargetHandler(BaseHTTPRequestHandler):
    """Simulates a small vulnerable web app for self-contained testing."""

    def log_message(self, format, *args):
        pass  # Quiet test output

    def do_GET(self):
        # 1. SPA Root with Links & Form
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html = """
            <!DOCTYPE html>
            <html>
            <head><title>Mock Target App</title></head>
            <body>
              <h1>Welcome to Test App</h1>
              <a href="/#/search">Search Products</a>
              <a href="/#/profile">User Profile</a>
              <form action="/api/search" method="GET">
                <input name="q" type="text" placeholder="Search keyword"/>
                <button type="submit">Search</button>
              </form>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))

        # 2. Vulnerable Search Endpoint (Simulates SQL Error Leak)
        elif self.path.startswith("/api/search"):
            is_sqli = "'" in self.path or "%27" in self.path or "UNION" in self.path
            self.send_response(500 if is_sqli else 200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if is_sqli:
                self.wfile.write(b'{"error": "sqlite3.OperationalError: near \'UNION\': syntax error"}')
            else:
                self.wfile.write(b'{"results": [{"id": 1, "name": "Apple"}]}')


        # 3. BOLA / IDOR endpoint: /api/orders/{id}
        elif self.path.startswith("/api/orders/"):
            # Header check
            auth = self.headers.get("Authorization", "")
            if "Bearer" in auth:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"order_id": 42, "victim_email": "victim@juice-sh.op", "amount": 100}')
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Unauthorized"}')

        else:
            self.send_response(404)
            self.end_headers()


@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("127.0.0.1", 0), MockTargetHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


# ── Pipeline E2E Integration Test ─────────────────────────────

@pytest.mark.asyncio
async def test_end_to_end_dast_pipeline(mock_server):
    target_url = mock_server

    # 1. Run Reconnaissance Crawler against the mock server
    cfg = CrawlerConfig(
        base_url=target_url,
        headless=True,
        timeout_ms=10_000,
        max_pages=5,
    )
    recon_output = await run_playwright_crawler(target_url=target_url, config=cfg)

    assert recon_output.target.is_reachable is True
    assert len(recon_output.routes) >= 1
    assert len(recon_output.forms) >= 1

    # 2. Test Verification on Simulated SQL Injection
    from exploit_runner import ExploitRunner
    runner = ExploitRunner(allowed_targets=["127.0.0.1"])
    verifier = VerificationEngine()
    fp_filter = FalsePositiveFilter()

    spec = TestSpecification(
        scan_id=recon_output.scan_id,
        vulnerability_type="SQLI",
        target_url=f"{target_url}/api/search",
        payload="' UNION SELECT * FROM users--",
        inject_in="query",
        param_name="q",
    )

    async with runner:
        result = await execute_and_verify(
            spec=spec,
            runner=runner,
            verifier=verifier,
            filter_engine=fp_filter,
        )

        assert result.status == VerificationStatus.VERIFIED
        assert result.is_confirmed is True
        assert "sqlite3.OperationalError" in result.observed_behavior

    # 3. Test BOLA / IDOR Verification (Victim data leak)
    bola_spec = TestSpecification(
        scan_id=recon_output.scan_id,
        vulnerability_type="BOLA",
        target_url=f"{target_url}/api/orders/42",
        auth_session="attacker",
        baseline_context={"victim_identifiers": ["victim@juice-sh.op"]},
    )
    tm = TokenManager()
    tm.ingest_from_headers({"authorization": "Bearer attacker_token_xyz"}, session_name="attacker")
    bola_runner = ExploitRunner(token_manager=tm, allowed_targets=["127.0.0.1"])

    async with bola_runner:
        bola_result = await execute_and_verify(
            spec=bola_spec,
            runner=bola_runner,
            verifier=verifier,
            filter_engine=fp_filter,
        )

        assert bola_result.status == VerificationStatus.VERIFIED
        assert bola_result.is_confirmed is True
        assert "victim@juice-sh.op" in bola_result.observed_behavior
