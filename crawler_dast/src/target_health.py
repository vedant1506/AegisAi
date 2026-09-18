"""
AegisAI — Target Health & Connectivity Checker
===============================================
Verifies reachability, responsiveness, and service health of configured
DAST targets (e.g. OWASP Juice Shop, OWASP crAPI, or custom testbeds).
"""

from __future__ import annotations

import asyncio
import os
import time
from urllib.parse import urlparse

import httpx
import structlog
from dotenv import load_dotenv

from models import TargetInfo

load_dotenv()
logger = structlog.get_logger(__name__)


async def check_target_health(
    base_url: str | None = None,
    timeout_seconds: float = 10.0,
) -> TargetInfo:
    """
    Probe the target URL for HTTP connectivity, status code, and latency.

    Args:
        base_url: Base URL to check. If None, loaded from TARGET_BASE_URL env.
        timeout_seconds: Max seconds to wait before declaring unreachable.

    Returns:
        TargetInfo dataclass populated with reachability diagnostics.
    """
    url = (base_url or os.getenv("TARGET_BASE_URL", "http://localhost:3000")).rstrip("/")
    parsed = urlparse(url)
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme or "http"

    info = TargetInfo(
        base_url=url,
        host=host,
        port=port,
        scheme=scheme,
        is_reachable=False,
        response_time_ms=0.0,
    )

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=httpx.Timeout(timeout_seconds),
        ) as client:
            resp = await client.get(url)
            elapsed_ms = (time.monotonic() - start) * 1000.0

            info.is_reachable = resp.status_code < 500
            info.response_time_ms = round(elapsed_ms, 2)
            info.server_banner = resp.headers.get("server") or resp.headers.get("x-powered-by")

            logger.info(
                "target.healthcheck.success",
                url=url,
                status=resp.status_code,
                duration_ms=info.response_time_ms,
                server=info.server_banner,
            )
            return info

    except httpx.ConnectError as exc:
        logger.warning("target.healthcheck.connect_failed", url=url, error=str(exc))
        return info
    except httpx.TimeoutException as exc:
        logger.warning("target.healthcheck.timeout", url=url, timeout=timeout_seconds)
        return info
    except Exception as exc:
        logger.error("target.healthcheck.error", url=url, error=str(exc))
        return info


def check_target_health_sync(
    base_url: str | None = None,
    timeout_seconds: float = 10.0,
) -> TargetInfo:
    """Synchronous wrapper for check_target_health."""
    return asyncio.run(check_target_health(base_url, timeout_seconds))


if __name__ == "__main__":
    target_env = os.getenv("TARGET_BASE_URL", "http://localhost:3000")
    print(f"\n[*] Probing AegisAI target health: {target_env} ...")
    health = check_target_health_sync(target_env, timeout_seconds=5.0)

    if health.is_reachable:
        print(f"[+] Target reachable: {health.base_url}")
        print(f"    Latency: {health.response_time_ms} ms")
        print(f"    Server:  {health.server_banner or 'Unknown'}")
    else:
        print(f"[-] Target unreachable at {health.base_url}")
        print("    Hint: If using Docker, ensure container is up (cd crawler_dast/target_docker && docker-compose up -d)")
        print("    Or set TARGET_BASE_URL to an active testbed instance.")
