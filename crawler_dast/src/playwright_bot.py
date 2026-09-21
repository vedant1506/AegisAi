"""
AegisAI — Playwright Autonomous DAST Reconnaissance Crawler
============================================================
Autonomous headless Chromium crawler for modern Single Page Applications (SPAs)
and REST/GraphQL APIs (OWASP Juice Shop, crAPI, and custom web applications).

Key Features:
  1. SPA Hash-Route preservation (supports Angular, React, Vue #/ routing).
  2. Dialog & modal auto-dismissal (e.g. Juice Shop Welcome Dialog & Cookie Consent).
  3. Form & parameter discovery (extracts inputs, actions, query keys).
  4. Network interception: observes request payloads and response status codes/headers.
  5. LocalStorage & cookie token harvesting passed to TokenManager.
  6. Loop-prevention and URL deduplication.
  7. Strong typing via DASTReconOutput and EndpointSchema export.
"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse
from uuid import uuid4

import structlog
from dotenv import load_dotenv
from playwright.async_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Response,
    async_playwright,
)

from models import (
    AuthMetadata,
    CrawlError,
    DASTReconOutput,
    DiscoveredAPI,
    DiscoveredForm,
    DiscoveredParameter,
    DiscoveredRoute,
    Observation,
    TargetInfo,
)
from token_manager import TokenManager

load_dotenv()
logger = structlog.get_logger(__name__)


# ── Crawler Configuration ─────────────────────────────────────

@dataclass
class CrawlerConfig:
    """Configurable knobs for the Playwright DAST Recon Bot."""

    base_url: str = os.getenv("TARGET_BASE_URL", "http://localhost:3000")
    headless: bool = os.getenv("HEADLESS", "true").lower() == "true"
    timeout_ms: int = int(os.getenv("CRAWLER_TIMEOUT_MS", "25000"))
    max_pages: int = int(os.getenv("CRAWLER_MAX_PAGES", "40"))
    max_depth: int = int(os.getenv("CRAWLER_MAX_DEPTH", "3"))
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 "
        "(AegisAI Autonomous VAPT Bot/1.0)"
    )
    # Target authentication credentials (default: OWASP Juice Shop admin)
    login_path: str = "/#/login"
    login_email: str = os.getenv("TARGET_USER_EMAIL", "admin@juice-sh.op")
    login_password: str = os.getenv("TARGET_USER_PASSWORD", "admin123")

    # Form selectors (with fallbacks)
    email_selectors: list[str] = field(
        default_factory=lambda: [
            'input[name="email"]',
            'input#email',
            'input[type="email"]',
            'input[placeholder*="email" i]',
        ]
    )
    password_selectors: list[str] = field(
        default_factory=lambda: [
            'input[name="password"]',
            'input#password',
            'input[type="password"]',
            'input[placeholder*="password" i]',
        ]
    )
    submit_selectors: list[str] = field(
        default_factory=lambda: [
            'button#loginButton',
            'button[type="submit"]',
            'button:has-text("Log in")',
            'button:has-text("Login")',
        ]
    )


# ── Playwright Bot ────────────────────────────────────────────

class PlaywrightBot:
    """
    Autonomous DAST Reconnaissance Agent.
    """

    def __init__(
        self,
        config: CrawlerConfig | None = None,
        token_manager: TokenManager | None = None,
        scan_id: str | None = None,
    ) -> None:
        self.config = config or CrawlerConfig()
        self.token_manager = token_manager or TokenManager()
        self.scan_id = scan_id or str(uuid4())

        self._discovered_routes: dict[str, DiscoveredRoute] = {}
        self._discovered_apis: dict[str, DiscoveredAPI] = {}
        self._discovered_forms: list[DiscoveredForm] = []
        self._discovered_parameters: dict[str, DiscoveredParameter] = {}
        self._observations: list[Observation] = []
        self._errors: list[CrawlError] = []

        self._visited_urls: set[str] = set()
        self._inflight_requests: dict[str, dict[str, Any]] = {}

    # ── Public Crawl Lifecycle ────────────────────────────────

    async def crawl(self) -> DASTReconOutput:
        """
        Execute full autonomous crawl:
          init → launch browser → dismiss modals → authenticate → explore routes → summarize.
        """
        started_at = datetime.utcnow()
        start_mono = time.monotonic()

        target_info = TargetInfo(
            base_url=self.config.base_url,
            is_reachable=False,
        )

        logger.info(
            "crawler.start",
            scan_id=self.scan_id,
            target=self.config.base_url,
            headless=self.config.headless,
        )

        async with async_playwright() as pw:
            try:
                browser = await pw.chromium.launch(
                    headless=self.config.headless,
                    args=[
                        "--no-sandbox",
                        "--disable-setuid-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-blink-features=AutomationControlled",
                    ],
                )
            except Exception as exc:
                logger.error("crawler.browser_launch_failed", error=str(exc))
                self._errors.append(
                    CrawlError(
                        phase="browser_launch",
                        error_type="LaunchError",
                        message=str(exc),
                    )
                )
                return self._build_output(target_info, started_at, start_mono)

            context = await browser.new_context(
                user_agent=self.config.user_agent,
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 800},
            )
            context.set_default_timeout(self.config.timeout_ms)
            page = await context.new_page()

            # Attach request & response listeners
            self._attach_network_interceptors(page)

            try:
                # Step 1: Initial navigation & modal dismissal
                await self._navigate_safely(page, self.config.base_url)
                target_info.is_reachable = True
                await self._dismiss_popups(page)

                # Step 2: Attempt authenticated login
                await self._perform_login(page)

                # Step 3: Harvest tokens post-login
                await self.token_manager.ingest_from_page(page, session_name="default")

                # Step 4: Recursive SPA page crawl
                await self._crawl_routes(page)

                # Step 5: Final state & token refresh
                await self.token_manager.ingest_from_page(page, session_name="default")

            except Exception as exc:
                logger.error("crawler.execution_error", error=str(exc))
                self._errors.append(
                    CrawlError(
                        phase="crawl_execution",
                        error_type=exc.__class__.__name__,
                        message=str(exc),
                    )
                )
            finally:
                await browser.close()

        duration = time.monotonic() - start_mono
        logger.info(
            "crawler.completed",
            scan_id=self.scan_id,
            routes_found=len(self._discovered_routes),
            apis_found=len(self._discovered_apis),
            forms_found=len(self._discovered_forms),
            duration_seconds=round(duration, 2),
        )

        return self._build_output(target_info, started_at, start_mono)

    # ── Network Interception ──────────────────────────────────

    def _attach_network_interceptors(self, page: Page) -> None:
        """Monitor outgoing HTTP requests and incoming responses."""

        async def _on_request(request: Request) -> None:
            resource_type = request.resource_type
            if resource_type not in ("xhr", "fetch", "document", "websocket"):
                return

            url = request.url
            if not self._is_internal_url(url):
                return

            req_id = f"{request.method}:{url}:{time.monotonic()}"
            self._inflight_requests[request.url] = {
                "method": request.method,
                "url": url,
                "headers": dict(request.headers),
                "post_data": request.post_data,
                "start_time": time.monotonic(),
            }

            # Ingest any auth tokens from request headers on the fly
            self.token_manager.ingest_from_headers(request.headers, session_name="default")

        async def _on_response(response: Response) -> None:
            url = response.url
            if not self._is_internal_url(url):
                return

            req_info = self._inflight_requests.pop(url, None)
            method = req_info["method"] if req_info else response.request.method
            headers = req_info["headers"] if req_info else dict(response.request.headers)
            post_data = req_info["post_data"] if req_info else response.request.post_data
            duration_ms = (
                (time.monotonic() - req_info["start_time"]) * 1000.0 if req_info else 0.0
            )

            # Check response headers for tokens (e.g. Set-Cookie)
            self.token_manager.ingest_from_headers(response.headers, session_name="default")

            parsed = urlparse(url)
            clean_endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            query_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            # Track query parameters
            for param_name, param_val in query_params.items():
                param_key = f"{clean_endpoint}:{param_name}"
                if param_key not in self._discovered_parameters:
                    self._discovered_parameters[param_key] = DiscoveredParameter(
                        name=param_name,
                        location="query",
                        endpoint_url=clean_endpoint,
                        method=method,
                        sample_value=param_val,
                    )

            # Record API if xhr, fetch, or json
            content_type = response.headers.get("content-type", "")
            is_api = (
                response.request.resource_type in ("xhr", "fetch")
                or "application/json" in content_type
                or "/api/" in url
                or "/rest/" in url
            )

            if is_api:
                api_key = f"{method}:{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if api_key not in self._discovered_apis:
                    self._discovered_apis[api_key] = DiscoveredAPI(
                        url=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        method=method,
                        headers=headers,
                        query_params=query_params,
                        body_sample=post_data[:1024] if post_data else None,
                        response_status=response.status,
                        response_headers=dict(response.headers),
                        response_time_ms=round(duration_ms, 2),
                        content_type=content_type,
                        tokens={
                            "jwt": self.token_manager.get_jwt(),
                            "session_cookie": self.token_manager.get_session_cookie(),
                        },
                    )

        page.on("request", _on_request)
        page.on("response", _on_response)

    # ── Modal & Popup Dismissal ───────────────────────────────

    async def _dismiss_popups(self, page: Page) -> None:
        """
        Auto-dismiss intrusive popups like OWASP Juice Shop's Welcome Dialog
        and Cookie Consent banner that block click/input interactions.
        """
        logger.debug("crawler.dismissing_popups")

        # 1. Welcome Dialog Dismiss button
        dismiss_selectors = [
            'button[aria-label="Close Welcome Banner"]',
            'mat-dialog-container button:has-text("Dismiss")',
            'button:has-text("Dismiss")',
            '.close-dialog',
            'button.close-dialog',
        ]
        for sel in dismiss_selectors:
            try:
                elem = page.locator(sel).first
                if await elem.is_visible(timeout=1500):
                    await elem.click(timeout=2000)
                    logger.info("crawler.popup_dismissed", selector=sel)
                    await page.wait_for_timeout(300)
                    break
            except Exception:
                pass

        # 2. Cookie Consent banner ("Me want it!")
        cookie_selectors = [
            'a[aria-label="dismiss cookie message"]',
            'a.cc-btn.cc-dismiss',
            'a:has-text("Me want it!")',
            'button:has-text("Accept")',
        ]
        for sel in cookie_selectors:
            try:
                elem = page.locator(sel).first
                if await elem.is_visible(timeout=1500):
                    await elem.click(timeout=2000)
                    logger.info("crawler.cookie_banner_dismissed", selector=sel)
                    await page.wait_for_timeout(300)
                    break
            except Exception:
                pass

    # ── Authentication Flow ───────────────────────────────────

    async def _perform_login(self, page: Page) -> None:
        """Attempt to fill and submit target login form."""
        login_url = urljoin(self.config.base_url, self.config.login_path)
        logger.info("crawler.authenticating", url=login_url)

        try:
            await self._navigate_safely(page, login_url)
            await self._dismiss_popups(page)

            email_input = await self._find_first_matching(page, self.config.email_selectors)
            pass_input = await self._find_first_matching(page, self.config.password_selectors)
            submit_btn = await self._find_first_matching(page, self.config.submit_selectors)

            if email_input and pass_input:
                await email_input.fill(self.config.login_email)
                await pass_input.fill(self.config.login_password)

                if submit_btn:
                    await submit_btn.click()
                    await page.wait_for_timeout(1000)
                    logger.info("crawler.login_submitted", email=self.config.login_email)
                else:
                    await pass_input.press("Enter")
                    await page.wait_for_timeout(1000)

                await self._dismiss_popups(page)
            else:
                logger.debug("crawler.login_form_not_found", url=login_url)

        except Exception as exc:
            logger.warning("crawler.login_flow_failed", error=str(exc))
            self._observations.append(
                Observation(
                    category="auth",
                    message=f"Automated login did not complete: {exc}",
                    severity="LOW",
                )
            )

    # ── Route & Page Exploration ──────────────────────────────

    async def _crawl_routes(self, page: Page) -> None:
        """
        Crawl internal links and modern SPA hash routes (#/...) up to max_pages.
        """
        queue: list[str] = [self.config.base_url]
        self._visited_urls.add(self._canonicalize_url(self.config.base_url))

        # Seed known SPA routes for vulnerability testing targets
        known_spa_seeds = [
            "/#/search",
            "/#/score-board",
            "/#/recycle",
            "/#/contact",
            "/#/about",
            "/#/photo-wall",
            "/#/administration",
            "/#/basket",
        ]
        for seed in known_spa_seeds:
            seed_url = urljoin(self.config.base_url, seed)
            canon = self._canonicalize_url(seed_url)
            if canon not in self._visited_urls:
                queue.append(seed_url)
                self._visited_urls.add(canon)

        while queue and len(self._discovered_routes) < self.config.max_pages:
            current_url = queue.pop(0)

            try:
                resp = await self._navigate_safely(page, current_url)
                await self._dismiss_popups(page)

                status_code = resp.status if resp else 200
                content_type = resp.headers.get("content-type") if resp else "text/html"
                title = await page.title()

                parsed = urlparse(current_url)
                is_spa = bool(parsed.fragment)

                route_key = self._canonicalize_url(current_url)
                self._discovered_routes[route_key] = DiscoveredRoute(
                    path=parsed.path + (f"#{parsed.fragment}" if parsed.fragment else ""),
                    full_url=current_url,
                    method="GET",
                    status_code=status_code,
                    content_type=content_type,
                    page_title=title,
                    is_spa_route=is_spa,
                )

                # Inspect DOM for forms and inputs
                await self._discover_forms_on_page(page, current_url)

                # Collect new hyperlinks and SPA anchors
                links = await page.eval_on_selector_all(
                    "a[href]", "elements => elements.map(e => e.getAttribute('href'))"
                )

                for link in links:
                    if not link or link.startswith(("javascript:", "mailto:", "tel:")):
                        continue

                    resolved = urljoin(current_url, link)
                    if not self._is_internal_url(resolved):
                        continue

                    canon = self._canonicalize_url(resolved)
                    if canon not in self._visited_urls and len(self._visited_urls) < (self.config.max_pages * 2):
                        self._visited_urls.add(canon)
                        queue.append(resolved)

            except Exception as exc:
                logger.debug("crawler.page_crawl_failed", url=current_url, error=str(exc))

    async def _discover_forms_on_page(self, page: Page, page_url: str) -> None:
        """Extract form structures and input parameters from the rendered DOM."""
        try:
            forms_data = await page.evaluate(
                """() => {
                    const forms = Array.from(document.querySelectorAll('form'));
                    return forms.map(f => {
                        const inputs = Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                            name: i.name || i.id || '',
                            type: i.type || 'text',
                            value: i.value || ''
                        }));
                        return {
                            action: f.action || '',
                            method: (f.method || 'POST').toUpperCase(),
                            inputs: inputs,
                            has_csrf: inputs.some(i => i.name.toLowerCase().includes('csrf'))
                        };
                    });
                }"""
            )

            for f in forms_data:
                action = f.get("action") or page_url
                resolved_action = urljoin(page_url, action)

                form_obj = DiscoveredForm(
                    action_url=resolved_action,
                    method=f.get("method", "POST"),
                    page_url=page_url,
                    inputs=f.get("inputs", []),
                    has_csrf=f.get("has_csrf", False),
                )
                self._discovered_forms.append(form_obj)

                for inp in f.get("inputs", []):
                    name = inp.get("name")
                    if name:
                        pkey = f"{resolved_action}:{name}"
                        if pkey not in self._discovered_parameters:
                            self._discovered_parameters[pkey] = DiscoveredParameter(
                                name=name,
                                location="body" if form_obj.method == "POST" else "query",
                                endpoint_url=resolved_action,
                                method=form_obj.method,
                                sample_value=inp.get("value"),
                            )

        except Exception as exc:
            logger.debug("crawler.form_extraction_error", error=str(exc))

    # ── Utilities ─────────────────────────────────────────────

    async def _navigate_safely(self, page: Page, url: str) -> Response | None:
        """Navigate with fallback load states."""
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=self.config.timeout_ms)
            await page.wait_for_timeout(400)
            return resp
        except Exception:
            # Settle on timeout
            return None

    async def _find_first_matching(self, page: Page, selectors: list[str]) -> Any | None:
        for sel in selectors:
            try:
                loc = page.locator(sel).first
                if await loc.is_visible(timeout=1000):
                    return loc
            except Exception:
                pass
        return None

    def _is_internal_url(self, url: str) -> bool:
        parsed_target = urlparse(self.config.base_url)
        parsed_url = urlparse(url)
        return parsed_url.netloc == parsed_target.netloc

    def _canonicalize_url(self, url: str) -> str:
        """
        Normalize URLs while preserving SPA hash fragments (#/...)
        and stripping trailing query noise for route deduplication.
        """
        parsed = urlparse(url)
        clean_path = parsed.path.rstrip("/") or "/"
        clean_frag = f"#{parsed.fragment}" if parsed.fragment else ""
        return f"{parsed.scheme}://{parsed.netloc}{clean_path}{clean_frag}"

    def _build_output(
        self,
        target_info: TargetInfo,
        started_at: datetime,
        start_mono: float,
    ) -> DASTReconOutput:
        """Construct the final DASTReconOutput contract."""
        duration = time.monotonic() - start_mono
        summary = self.token_manager.get_bundle_summary("default")

        roles = summary.get("jwt_roles", [])
        if isinstance(roles, str):
            roles = [roles] if roles else []

        auth_meta = AuthMetadata(
            has_jwt=summary.get("has_jwt", False),
            jwt_subject=summary.get("jwt_subject"),
            jwt_roles=roles,
            jwt_expired=summary.get("jwt_expired", False),
            has_session_cookie=summary.get("has_session_cookie", False),
            cookie_names=summary.get("cookie_names", []),
            has_csrf_token=summary.get("has_csrf_token", False),
            has_api_key=summary.get("has_api_key", False),
            active_sessions=self.token_manager.list_sessions(),
        )

        return DASTReconOutput(
            scan_id=self.scan_id,
            target=target_info,
            started_at=started_at,
            completed_at=datetime.utcnow(),
            duration_seconds=round(duration, 2),
            routes=list(self._discovered_routes.values()),
            apis=list(self._discovered_apis.values()),
            forms=self._discovered_forms,
            parameters=list(self._discovered_parameters.values()),
            authentication=auth_meta,
            observations=self._observations,
            errors=self._errors,
        )


# ── Integration Entrypoint ────────────────────────────────────

async def run_playwright_crawler(
    target_url: str | None = None,
    scan_id: str | None = None,
    config: CrawlerConfig | None = None,
) -> DASTReconOutput:
    """
    Public entry point for FastAPI backend and LangGraph agent pipelines.
    """
    cfg = config or CrawlerConfig()
    if target_url:
        cfg.base_url = target_url
    bot = PlaywrightBot(config=cfg, scan_id=scan_id)
    return await bot.crawl()


# ── Standalone CLI ────────────────────────────────────────────

if __name__ == "__main__":
    target = os.getenv("TARGET_BASE_URL", "http://localhost:3000")
    print(f"[*] Starting AegisAI DAST Reconnaissance on: {target}")

    output = asyncio.run(run_playwright_crawler(target_url=target))

    print(f"\n[+] Scan Completed in {output.duration_seconds}s")
    print(f"    Discovered Routes: {len(output.routes)}")
    print(f"    Discovered APIs:   {len(output.apis)}")
    print(f"    Discovered Forms:  {len(output.forms)}")
    print(f"    Parameters:        {len(output.parameters)}")
    print(f"    Authenticated:     {output.authentication.has_jwt or output.authentication.has_session_cookie}")

    if output.apis:
        print("\n[*] Sample APIs Captured:")
        for api in output.apis[:8]:
            print(f"    [{api.method:6}] {api.url} (Status: {api.response_status})")
