"""
AegisAI — Reproducibility Verification Script
Runs two controlled Playwright crawls against OWASP Juice Shop using identical configuration
to determine whether discovery counts (routes, APIs, forms, parameters) are reproducible.
"""

import asyncio
import json
import os
import sys
import time
from pathlib import Path

# Add crawler_dast/src to path
DAST_SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(DAST_SRC))

from playwright_bot import CrawlerConfig, PlaywrightBot
from models import DASTReconOutput


async def run_single_crawl(run_label: str, config: CrawlerConfig) -> dict:
    print(f"\n--- Starting {run_label} ---")
    bot = PlaywrightBot(config=config, scan_id=f"repro-{run_label}")
    t0 = time.perf_counter()
    output: DASTReconOutput = await bot.crawl()
    wall_duration = time.perf_counter() - t0

    result = {
        "label": run_label,
        "routes_count": len(output.routes),
        "apis_count": len(output.apis),
        "forms_count": len(output.forms),
        "parameters_count": len(output.parameters),
        "wall_duration_seconds": round(wall_duration, 2),
        "reported_duration_seconds": round(output.duration_seconds, 2),
        "routes": sorted([r.path for r in output.routes]),
        "apis": sorted([f"[{a.method}] {a.url}" for a in output.apis]),
        "jwt_harvested": output.authentication.has_jwt,
    }

    print(f"[{run_label}] Routes:     {result['routes_count']}")
    print(f"[{run_label}] APIs:       {result['apis_count']}")
    print(f"[{run_label}] Forms:      {result['forms_count']}")
    print(f"[{run_label}] Parameters: {result['parameters_count']}")
    print(f"[{run_label}] Duration:   {result['wall_duration_seconds']}s")
    print(f"[{run_label}] JWT:        {result['jwt_harvested']}")
    return result


async def main():
    target_url = "http://localhost:3000"
    
    # Controlled configuration
    cfg = CrawlerConfig(
        base_url=target_url,
        headless=True,
        timeout_ms=15_000,
        max_pages=8,
        max_depth=2,
        login_email="admin@juice-sh.op",
        login_password="admin123",
    )

    print(f"Target: {target_url}")
    print(f"Config: max_pages={cfg.max_pages}, max_depth={cfg.max_depth}, timeout={cfg.timeout_ms}ms")

    run1 = await run_single_crawl("Run_1", cfg)
    await asyncio.sleep(2)  # Short pause between runs
    run2 = await run_single_crawl("Run_2", cfg)

    print("\n" + "=" * 60)
    print("REPRODUCIBILITY COMPARISON")
    print("=" * 60)
    print(f"{'Metric':<20} | {'Run 1':<15} | {'Run 2':<15} | {'Diff':<10}")
    print("-" * 60)
    for m in ["routes_count", "apis_count", "forms_count", "parameters_count", "wall_duration_seconds"]:
        val1 = run1[m]
        val2 = run2[m]
        diff = val2 - val1 if isinstance(val1, (int, float)) else "N/A"
        print(f"{m:<20} | {str(val1):<15} | {str(val2):<15} | {str(diff):<10}")

    route_overlap = set(run1["routes"]).intersection(set(run2["routes"]))
    api_overlap = set(run1["apis"]).intersection(set(run2["apis"]))
    print("-" * 60)
    print(f"Route Jaccard similarity: {len(route_overlap)}/{len(set(run1['routes']).union(set(run2['routes'])))}")
    print(f"API Jaccard similarity:   {len(api_overlap)}/{len(set(run1['apis']).union(set(run2['apis'])))}")

    # Save to disk for reference
    out_file = Path(__file__).resolve().parent / "results" / "reproducibility_audit.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({"run1": run1, "run2": run2}, f, indent=2)
    print(f"\n[+] Detailed comparison saved to {out_file}")


if __name__ == "__main__":
    asyncio.run(main())
