"""INTEL — Threat Intelligence API Wrappers.

Real HTTP clients for HIBP, VirusTotal, Shodan, Censys, GreyNoise, Pulsedive.
Flare and SpyCloud require paid enterprise access — report as such.
"""
from __future__ import annotations
import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx

from raven.models.core import (
    BreachRecord, FindingSeverity, IntelFinding, IntelSource, ParsedQuery,
)

logger = logging.getLogger(__name__)

_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


def _get_key(api_keys: dict, name: str) -> str:
    """Get API key from dict or environment variable."""
    return api_keys.get(name, "") or os.environ.get(name.upper().replace("-", "_"), "")


class IntelEngine:
    """Threat intelligence API client — queries multiple sources."""

    def __init__(self, api_keys: Optional[dict[str, str]] = None):
        self._api_keys = api_keys or {}
        self._client = httpx.Client(timeout=_TIMEOUT, follow_redirects=True)
        self._clients = {
            IntelSource.HIBP: self._query_hibp,
            IntelSource.VIRUSTOTAL: self._query_virustotal,
            IntelSource.SHODAN: self._query_shodan,
            IntelSource.CENSYS: self._query_censys,
            IntelSource.FLARE: self._query_flare,
            IntelSource.SPYCLOUD: self._query_spycloud,
            IntelSource.GREYNOISE: self._query_greynoise,
            IntelSource.PULSEDIVE: self._query_pulsedive,
        }

    def query(self, parsed: ParsedQuery) -> list[IntelFinding]:
        """Query all relevant sources for a parsed query."""
        findings = []
        for source in parsed.sources_to_query:
            client = self._clients.get(source)
            if client:
                try:
                    results = client(parsed.targets, parsed.intent.value)
                    findings.extend(results)
                except Exception as e:
                    logger.warning("Source %s failed: %s", source.value, e)
        return findings

    def query_source(self, source: IntelSource, targets: list[str]) -> list[IntelFinding]:
        """Query a specific source."""
        client = self._clients.get(source)
        return client(targets, "general") if client else []

    def get_breaches(self, email: str) -> list[BreachRecord]:
        """Check email against HIBP breach database."""
        key = _get_key(self._api_keys, "hibp_api_key")
        if not key:
            logger.info("HIBP API key required for breach lookup. Set HIBP_API_KEY.")
            return []

        try:
            resp = self._client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": key,
                    "User-Agent": "RedSpecter-RAVEN",
                },
                params={"truncateResponse": "false"},
            )
            if resp.status_code == 200:
                breaches = resp.json()
                return [
                    BreachRecord(
                        email=email,
                        breach_name=b.get("Name", "Unknown"),
                        breach_date=b.get("BreachDate", ""),
                        data_types=b.get("DataClasses", []),
                        is_verified=b.get("IsVerified", False),
                        source=IntelSource.HIBP,
                    )
                    for b in breaches
                ]
            elif resp.status_code == 404:
                return []  # No breaches found
            elif resp.status_code == 401:
                logger.warning("HIBP API key invalid")
        except httpx.HTTPError as e:
            logger.warning("HIBP breach lookup failed: %s", e)
        return []

    def _query_hibp(self, targets: list[str], intent: str) -> list[IntelFinding]:
        """Query Have I Been Pwned for breach data."""
        key = _get_key(self._api_keys, "hibp_api_key")
        findings = []

        for target in targets:
            if not key:
                # Use the free password hash API (no key needed)
                findings.append(self._hibp_password_check(target))
                continue

            try:
                resp = self._client.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}",
                    headers={
                        "hibp-api-key": key,
                        "User-Agent": "RedSpecter-RAVEN",
                    },
                    params={"truncateResponse": "true"},
                )
                if resp.status_code == 200:
                    breaches = resp.json()
                    breach_names = [b.get("Name", "?") for b in breaches]
                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.HIBP,
                        finding_type="breach_check",
                        title=f"HIBP: {len(breaches)} breaches for {target}",
                        detail=f"Breaches: {', '.join(breach_names[:10])}",
                        severity=FindingSeverity.HIGH if len(breaches) > 2 else FindingSeverity.MEDIUM,
                        target=target, confidence=0.95,
                        discovered_at=datetime.now(timezone.utc), actionable=True,
                    ))
                elif resp.status_code == 404:
                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.HIBP,
                        finding_type="breach_check",
                        title=f"HIBP: No breaches found for {target}",
                        severity=FindingSeverity.INFO, target=target, confidence=1.0,
                        discovered_at=datetime.now(timezone.utc),
                    ))
            except httpx.HTTPError as e:
                logger.debug("HIBP query failed for %s: %s", target, e)

        return findings

    def _hibp_password_check(self, target: str) -> IntelFinding:
        """Free HIBP password hash range check (no API key needed)."""
        # Hash the target and check against k-anonymity API
        sha1 = hashlib.sha1(target.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]

        try:
            resp = self._client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if resp.status_code == 200:
                count = 0
                for line in resp.text.splitlines():
                    hash_suffix, c = line.split(":")
                    if hash_suffix == suffix:
                        count = int(c)
                        break
                if count > 0:
                    return IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.HIBP,
                        finding_type="password_exposure",
                        title=f"HIBP: Password hash seen {count:,} times",
                        detail=f"SHA1 prefix: {prefix}... found in breach corpus",
                        severity=FindingSeverity.HIGH, target=target, confidence=1.0,
                        discovered_at=datetime.now(timezone.utc), actionable=True,
                    )
        except httpx.HTTPError:
            pass

        return IntelFinding(
            finding_id=uuid.uuid4().hex[:10], source=IntelSource.HIBP,
            finding_type="password_check", title=f"HIBP: Password not found in breaches",
            severity=FindingSeverity.INFO, target=target, confidence=1.0,
            discovered_at=datetime.now(timezone.utc),
        )

    def _query_virustotal(self, targets: list[str], intent: str) -> list[IntelFinding]:
        """Query VirusTotal for domain/IP/file reputation."""
        key = _get_key(self._api_keys, "vt_api_key")
        if not key:
            return [IntelFinding(
                finding_id=uuid.uuid4().hex[:10], source=IntelSource.VIRUSTOTAL,
                finding_type="skipped", title="VirusTotal: API key required",
                detail="Set VT_API_KEY environment variable",
                severity=FindingSeverity.INFO, target=targets[0] if targets else "",
                confidence=0, discovered_at=datetime.now(timezone.utc),
            )]

        findings = []
        headers = {"x-apikey": key}

        for target in targets:
            # Determine if IP or domain
            if all(c.isdigit() or c == "." for c in target):
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            else:
                url = f"https://www.virustotal.com/api/v3/domains/{target}"

            try:
                resp = self._client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) if stats else 0
                    reputation = data.get("reputation", 0)

                    severity = FindingSeverity.INFO
                    if malicious > 0:
                        severity = FindingSeverity.CRITICAL if malicious > 5 else FindingSeverity.HIGH
                    elif suspicious > 0:
                        severity = FindingSeverity.MEDIUM

                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.VIRUSTOTAL,
                        finding_type="reputation",
                        title=f"VT: {malicious}/{total} detections for {target}",
                        detail=f"Malicious: {malicious}, Suspicious: {suspicious}, Reputation: {reputation}",
                        severity=severity, target=target, confidence=0.9,
                        discovered_at=datetime.now(timezone.utc), actionable=malicious > 0,
                    ))
                elif resp.status_code == 404:
                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.VIRUSTOTAL,
                        finding_type="reputation", title=f"VT: No data for {target}",
                        severity=FindingSeverity.INFO, target=target, confidence=0.5,
                        discovered_at=datetime.now(timezone.utc),
                    ))
            except httpx.HTTPError as e:
                logger.debug("VT query failed for %s: %s", target, e)

        return findings

    def _query_shodan(self, targets: list[str], intent: str) -> list[IntelFinding]:
        """Query Shodan for infrastructure intelligence."""
        key = _get_key(self._api_keys, "shodan_api_key")
        if not key:
            return [IntelFinding(
                finding_id=uuid.uuid4().hex[:10], source=IntelSource.SHODAN,
                finding_type="skipped", title="Shodan: API key required",
                detail="Set SHODAN_API_KEY environment variable",
                severity=FindingSeverity.INFO, target=targets[0] if targets else "",
                confidence=0, discovered_at=datetime.now(timezone.utc),
            )]

        findings = []
        for target in targets:
            # Resolve to IP if domain
            import socket
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                ip = target

            try:
                resp = self._client.get(
                    f"https://api.shodan.io/shodan/host/{ip}",
                    params={"key": key},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    ports = data.get("ports", [])
                    vulns = data.get("vulns", [])
                    org = data.get("org", "Unknown")
                    os_name = data.get("os", "Unknown")
                    country = data.get("country_name", "Unknown")

                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.SHODAN,
                        finding_type="infrastructure",
                        title=f"Shodan: {len(ports)} ports on {ip} ({target})",
                        detail=f"Ports: {ports[:15]} | Org: {org} | OS: {os_name} | Country: {country}",
                        severity=FindingSeverity.MEDIUM, target=target, confidence=0.95,
                        discovered_at=datetime.now(timezone.utc), actionable=True,
                    ))
                    if vulns:
                        findings.append(IntelFinding(
                            finding_id=uuid.uuid4().hex[:10], source=IntelSource.SHODAN,
                            finding_type="vulnerability",
                            title=f"Shodan: {len(vulns)} CVEs on {ip}",
                            detail=f"CVEs: {', '.join(vulns[:10])}",
                            severity=FindingSeverity.HIGH, target=target, confidence=0.9,
                            discovered_at=datetime.now(timezone.utc), actionable=True,
                        ))
            except httpx.HTTPError as e:
                logger.debug("Shodan query failed for %s: %s", target, e)

        return findings

    def _query_censys(self, targets: list[str], intent: str) -> list[IntelFinding]:
        """Query Censys for certificate and host data."""
        api_id = _get_key(self._api_keys, "censys_api_id")
        api_secret = _get_key(self._api_keys, "censys_api_secret")

        if not api_id or not api_secret:
            return [IntelFinding(
                finding_id=uuid.uuid4().hex[:10], source=IntelSource.CENSYS,
                finding_type="skipped", title="Censys: API credentials required",
                detail="Set CENSYS_API_ID and CENSYS_API_SECRET",
                severity=FindingSeverity.INFO, target=targets[0] if targets else "",
                confidence=0, discovered_at=datetime.now(timezone.utc),
            )]

        findings = []
        for target in targets:
            try:
                resp = self._client.get(
                    "https://search.censys.io/api/v2/certificates/search",
                    params={"q": target, "per_page": 10},
                    auth=(api_id, api_secret),
                )
                if resp.status_code == 200:
                    data = resp.json()
                    hits = data.get("result", {}).get("hits", [])
                    names = set()
                    for hit in hits:
                        for name in hit.get("names", []):
                            names.add(name)
                    if hits:
                        findings.append(IntelFinding(
                            finding_id=uuid.uuid4().hex[:10], source=IntelSource.CENSYS,
                            finding_type="certificate",
                            title=f"Censys: {len(hits)} certs for {target}",
                            detail=f"SANs: {', '.join(sorted(names)[:15])}",
                            severity=FindingSeverity.INFO, target=target, confidence=0.85,
                            discovered_at=datetime.now(timezone.utc),
                        ))
            except httpx.HTTPError as e:
                logger.debug("Censys query failed for %s: %s", target, e)

        return findings

    def _query_flare(self, targets: list[str], intent: str) -> list[IntelFinding]:
        """Flare.io — requires enterprise subscription."""
        return [IntelFinding(
            finding_id=uuid.uuid4().hex[:10], source=IntelSource.FLARE,
            finding_type="requires_subscription",
            title=f"Flare: Enterprise subscription required for {t}",
            detail="Flare.io requires paid enterprise API access. Contact sales@flare.io",
            severity=FindingSeverity.INFO, target=t, confidence=0,
            discovered_at=datetime.now(timezone.utc),
        ) for t in targets]

    def _query_spycloud(self, targets: list[str], intent: str) -> list[IntelFinding]:
        """SpyCloud — requires enterprise subscription."""
        return [IntelFinding(
            finding_id=uuid.uuid4().hex[:10], source=IntelSource.SPYCLOUD,
            finding_type="requires_subscription",
            title=f"SpyCloud: Enterprise subscription required for {t}",
            detail="SpyCloud requires paid API access. Visit spycloud.com/products",
            severity=FindingSeverity.INFO, target=t, confidence=0,
            discovered_at=datetime.now(timezone.utc),
        ) for t in targets]

    def _query_greynoise(self, targets: list[str], intent: str) -> list[IntelFinding]:
        """Query GreyNoise Community API (free, no key needed)."""
        findings = []
        for target in targets:
            # Only works for IPs
            import socket
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                ip = target

            try:
                resp = self._client.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    noise = data.get("noise", False)
                    riot = data.get("riot", False)
                    classification = data.get("classification", "unknown")
                    name = data.get("name", "")
                    message = data.get("message", "")

                    severity = FindingSeverity.INFO
                    if classification == "malicious":
                        severity = FindingSeverity.HIGH
                    elif noise:
                        severity = FindingSeverity.MEDIUM

                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.GREYNOISE,
                        finding_type="noise_classification",
                        title=f"GreyNoise: {ip} classified as {classification}",
                        detail=f"Noise: {noise} | RIOT: {riot} | Name: {name} | {message}",
                        severity=severity, target=target, confidence=0.85,
                        discovered_at=datetime.now(timezone.utc),
                        actionable=classification == "malicious",
                    ))
                elif resp.status_code == 404:
                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.GREYNOISE,
                        finding_type="noise_classification",
                        title=f"GreyNoise: {ip} not observed",
                        severity=FindingSeverity.INFO, target=target, confidence=0.8,
                        discovered_at=datetime.now(timezone.utc),
                    ))
            except httpx.HTTPError as e:
                logger.debug("GreyNoise query failed for %s: %s", target, e)

        return findings

    def _query_pulsedive(self, targets: list[str], intent: str) -> list[IntelFinding]:
        """Query Pulsedive free API for threat indicators."""
        findings = []
        key = _get_key(self._api_keys, "pulsedive_api_key")

        for target in targets:
            try:
                params = {"indicator": target, "pretty": "1"}
                if key:
                    params["key"] = key
                resp = self._client.get(
                    "https://pulsedive.com/api/info.php",
                    params=params,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    risk = data.get("risk", "unknown")
                    risk_recommended = data.get("risk_recommended", "unknown")
                    threats = data.get("threats", [])
                    feeds = data.get("feeds", [])

                    severity = FindingSeverity.INFO
                    if risk in ("critical", "high"):
                        severity = FindingSeverity.HIGH
                    elif risk == "medium":
                        severity = FindingSeverity.MEDIUM

                    threat_names = [t.get("name", "?") for t in threats[:5]] if threats else []
                    feed_names = [f.get("name", "?") for f in feeds[:5]] if feeds else []

                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.PULSEDIVE,
                        finding_type="threat_indicator",
                        title=f"Pulsedive: {target} risk={risk}",
                        detail=f"Recommended: {risk_recommended} | Threats: {', '.join(threat_names)} | Feeds: {', '.join(feed_names)}",
                        severity=severity, target=target, confidence=0.8,
                        discovered_at=datetime.now(timezone.utc),
                        actionable=risk in ("critical", "high"),
                    ))
                elif resp.status_code == 404:
                    findings.append(IntelFinding(
                        finding_id=uuid.uuid4().hex[:10], source=IntelSource.PULSEDIVE,
                        finding_type="threat_indicator",
                        title=f"Pulsedive: No data for {target}",
                        severity=FindingSeverity.INFO, target=target, confidence=0.5,
                        discovered_at=datetime.now(timezone.utc),
                    ))
            except httpx.HTTPError as e:
                logger.debug("Pulsedive query failed for %s: %s", target, e)

        return findings

    def get_available_sources(self) -> list[str]:
        return [s.value for s in IntelSource]
