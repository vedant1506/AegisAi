"""
Unit tests for PlaywrightBot URL canonicalization, SPA hash preservation, and config.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from playwright_bot import CrawlerConfig, PlaywrightBot


def test_crawler_config_defaults():
    config = CrawlerConfig()
    assert config.base_url == "http://localhost:3000"
    assert config.headless is True
    assert config.login_path == "/#/login"
    assert len(config.email_selectors) > 0


def test_spa_hash_route_preservation():
    bot = PlaywrightBot()

    # URL with hash route should keep the hash fragment intact!
    url_with_hash = "http://localhost:3000/#/score-board"
    canonical = bot._canonicalize_url(url_with_hash)
    assert canonical == "http://localhost:3000/#/score-board"

    # URL without hash
    url_plain = "http://localhost:3000/api/users/"
    canonical_plain = bot._canonicalize_url(url_plain)
    assert canonical_plain == "http://localhost:3000/api/users"


def test_internal_url_filtering():
    bot = PlaywrightBot(config=CrawlerConfig(base_url="http://localhost:3000"))

    assert bot._is_internal_url("http://localhost:3000/#/search") is True
    assert bot._is_internal_url("http://localhost:3000/api/Products") is True
    assert bot._is_internal_url("https://external-site.com/login") is False
    assert bot._is_internal_url("http://127.0.0.1:3000/login") is False
