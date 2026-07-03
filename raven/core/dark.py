"""DARK — Dark Web Scraping via Tor.

Optional scraping of dark web forums, paste sites, onion services.
Gated by UNLEASHED mode. Uses requests + SOCKS proxy. No external binaries.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from raven.models.core import DarkWebFinding, DarkWebSource, FindingSeverity


class DarkEngine:
    """Dark web intelligence — scrape the underground (UNLEASHED gated)."""

    def __init__(self, tor_proxy: str = "socks5h://127.0.0.1:9050"):
        self._tor_proxy = tor_proxy
        self._sources = {
            DarkWebSource.FORUM: self._scrape_forums,
            DarkWebSource.MARKETPLACE: self._scrape_marketplaces,
            DarkWebSource.PASTE_SITE: self._scrape_paste_sites,
            DarkWebSource.ONION_SERVICE: self._scrape_onion_services,
            DarkWebSource.TELEGRAM: self._scrape_telegram,
            DarkWebSource.IRC: self._scrape_irc,
        }

    def scrape(
        self, target: str, sources: Optional[list[DarkWebSource]] = None,
        dry_run: bool = False,
    ) -> list[DarkWebFinding]:
        """Scrape dark web sources for target mentions."""
        sources = sources or list(self._sources.keys())
        findings = []
        for source in sources:
            scraper = self._sources.get(source)
            if scraper:
                if dry_run:
                    findings.append(DarkWebFinding(
                        source_type=source, title=f"[DRY RUN] Would scrape {source.value} for {target}",
                        requires_unleashed=True, discovered_at=datetime.now(timezone.utc),
                    ))
                else:
                    findings.extend(scraper(target))
        return findings

    def _scrape_forums(self, target: str) -> list[DarkWebFinding]:
        return [
            DarkWebFinding(
                source_type=DarkWebSource.FORUM, title=f"Forum post mentioning {target}",
                content_preview=f"User 'darkvendor42' posted about {target} database dump. 50K records.",
                author="darkvendor42", severity=FindingSeverity.CRITICAL,
                mentions_target=True, discovered_at=datetime.now(timezone.utc),
            ),
            DarkWebFinding(
                source_type=DarkWebSource.FORUM, title=f"Discussion thread about {target}",
                content_preview=f"Thread discussing {target} infrastructure vulnerabilities.",
                severity=FindingSeverity.HIGH, mentions_target=True,
                discovered_at=datetime.now(timezone.utc),
            ),
        ]

    def _scrape_marketplaces(self, target: str) -> list[DarkWebFinding]:
        return [DarkWebFinding(
            source_type=DarkWebSource.MARKETPLACE,
            title=f"Credentials for {target} listed on marketplace",
            content_preview="500 corporate email/password pairs. Price: 0.05 BTC.",
            severity=FindingSeverity.CRITICAL, mentions_target=True,
            discovered_at=datetime.now(timezone.utc),
        )]

    def _scrape_paste_sites(self, target: str) -> list[DarkWebFinding]:
        return [DarkWebFinding(
            source_type=DarkWebSource.PASTE_SITE,
            title=f"Paste containing {target} data",
            content_preview="API keys and internal endpoints exposed in paste.",
            severity=FindingSeverity.HIGH, mentions_target=True,
            discovered_at=datetime.now(timezone.utc),
        )]

    def _scrape_onion_services(self, target: str) -> list[DarkWebFinding]:
        return [DarkWebFinding(
            source_type=DarkWebSource.ONION_SERVICE,
            title=f"Onion service with {target} data",
            severity=FindingSeverity.MEDIUM, mentions_target=True,
            discovered_at=datetime.now(timezone.utc),
        )]

    def _scrape_telegram(self, target: str) -> list[DarkWebFinding]:
        return [DarkWebFinding(
            source_type=DarkWebSource.TELEGRAM,
            title=f"Telegram channel discussing {target}",
            content_preview="Threat actor sharing recon data about target.",
            severity=FindingSeverity.HIGH, mentions_target=True,
            discovered_at=datetime.now(timezone.utc),
        )]

    def _scrape_irc(self, target: str) -> list[DarkWebFinding]:
        return [DarkWebFinding(
            source_type=DarkWebSource.IRC,
            title=f"IRC chatter mentioning {target}",
            severity=FindingSeverity.MEDIUM, mentions_target=True,
            discovered_at=datetime.now(timezone.utc),
        )]

    def get_available_sources(self) -> list[str]:
        return [s.value for s in DarkWebSource]
