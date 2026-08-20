"""
AegisAI — Playwright Async Headless Crawler Bot
=================================================
Drives a headless Chromium browser to:
  1. Navigate to the target application
  2. Perform an authenticated login flow
  3. Crawl all reachable pages & intercept XHR/Fetch requests
  4. Capture discovered endpoints for the DAST pipeline

The intercepted network requests are normalised into EndpointSchema
objects and returned to the orchestrating scan pipeline.

Usage:
    bot = PlaywrightBot(base_url="http://localhost:3000")
    endpoints = await bot.crawl()

Or run standalone for testing:
    python src/playwright_bot.py
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import structlog
from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    async_playwright,
)

logger = structlog.get_logger(__name__)


# ── Configuration ─────────────────────────────────────────────

@dataclass
class CrawlerConfig:
    """Tunable knobs for the Playwright bot."""

    base_url: str = "http://localhost:3000"
    headless: bool = True
    timeout_ms: int = 30_000
    max_pages: int = 50
    user_agent: str = (
        "Mozilla/5.0 (AegisAI/0.1; Security Research Bot) "
        "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
    )
    # Login credentials for the target app (OWASP Juice Shop defaults)
    login_email: str = "admin@juice-sh.op"
    login_password: str = "admin123"
    login_path: str = "/#/login"
    # CSS selectors for login form (Juice Shop specific — override as needed)
    email_selector: str = 'input[name="email"]'
    password_selector: str = 'input[name="password"]'
    submit_selector: str = 'button[type="submit"]'


# ── Discovered Endpoint ────────────────────────────────────────

@dataclass
class RawEndpoint:
    """Lightweight capture of an intercepted HTTP request."""

    url: str
    method: str
    headers: dict[str, str] = field(default_factory=dict)
    post_data: str | None = None
    resource_type: str = "fetch"


# ── Playwright Bot ────────────────────────────────────────────

class PlaywrightBot:
    """
    Async headless browser crawler built on Playwright.

    Thread safety: Each scan job should instantiate its own PlaywrightBot.
    """

    def __init__(self, config: CrawlerConfig | None = None) -> None:
        self.config = config or CrawlerConfig()
        self._discovered: dict[str, RawEndpoint] = {}  # url → endpoint (dedup)
        self._visited_pages: set[str] = set()

    # ── Public API ────────────────────────────────────────────

    async def crawl(self) -> list[RawEndpoint]:
        """
        Full crawl lifecycle:
          launch → authenticate → crawl pages → teardown

        Returns:
            List of unique RawEndpoint objects discovered during the crawl.
        """
        async with async_playwright() as pw:
            browser = await self._launch_browser(pw)
            context = await self._create_context(browser)
            page = await context.new_page()

            self._attach_network_interceptor(page)

            try:
                await self._authenticate(page)
                await self._crawl_pages(page, context)
            except Exception as exc:
                logger.error("crawler.error", error=str(exc))
            finally:
                await browser.close()

        endpoints = list(self._discovered.values())
        logger.info("crawler.complete", endpoint_count=len(endpoints))
        return endpoints

    # ── Browser Setup ─────────────────────────────────────────

    async def _launch_browser(self, pw: Any) -> Browser:
        logger.info(
            "crawler.launch",
            headless=self.config.headless,
            target=self.config.base_url,
        )
        return await pw.chromium.launch(
            headless=self.config.headless,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
            ],
        )

    async def _create_context(self, browser: Browser) -> BrowserContext:
        context = await browser.new_context(
            user_agent=self.config.user_agent,
            ignore_https_errors=True,
            viewport={"width": 1280, "height": 800},
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9"},
        )
        context.set_default_timeout(self.config.timeout_ms)
        return context

    # ── Network Interception ──────────────────────────────────

    def _attach_network_interceptor(self, page: Page) -> None:
        """Register a request listener to capture all API calls."""

        async def _on_request(request: Request) -> None:
            # Only capture API/XHR/Fetch traffic (skip static assets)
            if request.resource_type not in ("xhr", "fetch", "websocket"):
                return

            url = request.url
            if not url.startswith(self.config.base_url):
                return  # Ignore third-party requests

            key = f"{request.method}:{url}"
            if key not in self._discovered:
                self._discovered[key] = RawEndpoint(
                    url=url,
                    method=request.method,
                    headers=dict(request.headers),
                    post_data=request.post_data,
                    resource_type=request.resource_type,
                )
                logger.debug(
                    "crawler.endpoint_found",
                    method=request.method,
                    url=url,
                )

        page.on("request", _on_request)

    # ── Authentication ────────────────────────────────────────

    async def _authenticate(self, page: Page) -> None:
        """
        Perform login flow to obtain auth tokens.
        Tailored for OWASP Juice Shop; override selectors for other targets.

        TODO: After login, pass the JWT/cookie to TokenManager for storage.
        """
        login_url = urljoin(self.config.base_url, self.config.login_path)
        logger.info("crawler.authenticate", login_url=login_url)

        await page.goto(login_url, wait_until="networkidle")

        # Wait for form to render
        await page.wait_for_selector(self.config.email_selector, timeout=10_000)

        await page.fill(self.config.email_selector, self.config.login_email)
        await page.fill(self.config.password_selector, self.config.login_password)
        await page.click(self.config.submit_selector)

        # Wait for navigation post-login
        await page.wait_for_load_state("networkidle")
        logger.info("crawler.authenticated", url=page.url)

    # ── Page Crawling ─────────────────────────────────────────

    async def _crawl_pages(self, page: Page, context: BrowserContext) -> None:
        """
        BFS crawl of internal links starting from the base URL.

        TODO: Add form submission fuzzing to trigger more API endpoints.
        TODO: Handle SPAs that render content via JavaScript navigation events.
        """
        queue: list[str] = [self.config.base_url]
        self._visited_pages.add(self.config.base_url)

        while queue and len(self._visited_pages) < self.config.max_pages:
            url = queue.pop(0)
            logger.debug("crawler.visiting_page", url=url)

            try:
                await page.goto(url, wait_until="networkidle", timeout=self.config.timeout_ms)
                await page.wait_for_timeout(500)  # brief settle time

                # Collect internal links
                links = await page.eval_on_selector_all(
                    "a[href]",
                    "els => els.map(el => el.href)",
                )
                for link in links:
                    normalised = self._normalise_url(link)
                    if normalised and normalised not in self._visited_pages:
                        self._visited_pages.add(normalised)
                        queue.append(normalised)

            except Exception as exc:
                logger.warning("crawler.page_error", url=url, error=str(exc))

    def _normalise_url(self, url: str) -> str | None:
        """Return the URL if it's an internal link, else None."""
        parsed = urlparse(url)
        base_parsed = urlparse(self.config.base_url)
        if parsed.netloc != base_parsed.netloc:
            return None
        # Strip fragments (SPA hash routes handled via goto)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


# ── Standalone runner ─────────────────────────────────────────

async def _main() -> None:
    import os

    config = CrawlerConfig(
        base_url=os.getenv("TARGET_BASE_URL", "http://localhost:3000"),
        headless=os.getenv("HEADLESS", "true").lower() == "true",
    )
    bot = PlaywrightBot(config)
    endpoints = await bot.crawl()

    print(f"\n{'─' * 60}")
    print(f"  Discovered {len(endpoints)} unique API endpoints")
    print(f"{'─' * 60}")
    for ep in endpoints:
        print(f"  [{ep.method:6}] {ep.url}")


if __name__ == "__main__":
    asyncio.run(_main())
