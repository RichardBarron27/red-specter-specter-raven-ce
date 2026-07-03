"""PARSER — LLM-Powered Natural Language Query Interpretation.

Interprets user queries, maps intent to intel sources, extracts targets.
Uses local LLM (Ollama) or cloud API.
"""
from __future__ import annotations
import re
import uuid
from datetime import datetime, timezone
from typing import Optional
from raven.models.core import IntelSource, ParsedQuery, QueryIntent


class ParserEngine:
    """Natural language query parser — understands what you're asking for."""

    INTENT_KEYWORDS = {
        QueryIntent.BREACH_CHECK: ["breach", "breached", "pwned", "compromised", "leaked", "data leak"],
        QueryIntent.CREDENTIAL_LOOKUP: ["credentials", "password", "login", "email", "account", "creds"],
        QueryIntent.DOMAIN_INTEL: ["domain", "whois", "dns", "subdomain", "website", "site"],
        QueryIntent.IP_REPUTATION: ["ip", "address", "reputation", "malicious", "blocklist"],
        QueryIntent.DARK_WEB_MENTION: ["dark web", "darknet", "tor", "onion", "underground", "forum"],
        QueryIntent.THREAT_ACTOR: ["threat actor", "apt", "group", "campaign", "attacker", "adversary"],
        QueryIntent.VULNERABILITY_INTEL: ["vulnerability", "cve", "exploit", "vuln", "patch", "zero-day"],
        QueryIntent.INFRASTRUCTURE_INTEL: ["infrastructure", "server", "port", "service", "hosting", "cloud"],
        QueryIntent.MALWARE_ANALYSIS: ["malware", "ransomware", "trojan", "hash", "sample", "ioc"],
        QueryIntent.GENERAL_OSINT: ["osint", "intelligence", "info", "about", "tell me", "what do you know"],
    }

    SOURCE_MAP = {
        QueryIntent.BREACH_CHECK: [IntelSource.HIBP, IntelSource.SPYCLOUD, IntelSource.FLARE],
        QueryIntent.CREDENTIAL_LOOKUP: [IntelSource.HIBP, IntelSource.SPYCLOUD, IntelSource.FLARE],
        QueryIntent.DOMAIN_INTEL: [IntelSource.VIRUSTOTAL, IntelSource.CENSYS, IntelSource.SHODAN],
        QueryIntent.IP_REPUTATION: [IntelSource.VIRUSTOTAL, IntelSource.GREYNOISE, IntelSource.SHODAN],
        QueryIntent.DARK_WEB_MENTION: [IntelSource.FLARE, IntelSource.SPYCLOUD],
        QueryIntent.THREAT_ACTOR: [IntelSource.VIRUSTOTAL, IntelSource.PULSEDIVE],
        QueryIntent.VULNERABILITY_INTEL: [IntelSource.VIRUSTOTAL, IntelSource.SHODAN],
        QueryIntent.INFRASTRUCTURE_INTEL: [IntelSource.SHODAN, IntelSource.CENSYS, IntelSource.GREYNOISE],
        QueryIntent.MALWARE_ANALYSIS: [IntelSource.VIRUSTOTAL, IntelSource.PULSEDIVE],
        QueryIntent.GENERAL_OSINT: [IntelSource.SHODAN, IntelSource.VIRUSTOTAL, IntelSource.CENSYS],
    }

    def __init__(self, backend: str = "local"):
        self._backend = backend

    def parse(self, query: str) -> ParsedQuery:
        """Parse a natural language query into structured intent."""
        intent = self._classify_intent(query)
        targets = self._extract_targets(query)
        sources = self.SOURCE_MAP.get(intent, [IntelSource.VIRUSTOTAL])
        confidence = self._score_confidence(query, intent)

        return ParsedQuery(
            raw_query=query,
            intent=intent,
            targets=targets,
            sources_to_query=sources,
            confidence=confidence,
            parsed_at=datetime.now(timezone.utc),
        )

    def _classify_intent(self, query: str) -> QueryIntent:
        """Classify the intent of a query using keyword matching."""
        query_lower = query.lower()
        scores = {}
        for intent, keywords in self.INTENT_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in query_lower)
            if score > 0:
                scores[intent] = score
        if scores:
            return max(scores, key=scores.get)
        return QueryIntent.GENERAL_OSINT

    def _extract_targets(self, query: str) -> list[str]:
        """Extract target identifiers from the query."""
        targets = []
        # Email pattern
        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', query)
        targets.extend(emails)
        # Domain pattern
        domains = re.findall(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', query.lower())
        targets.extend([d for d in domains if d not in emails and len(d) > 4])
        # IP pattern
        ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', query)
        targets.extend(ips)
        # CVE pattern
        cves = re.findall(r'CVE-\d{4}-\d{4,}', query, re.IGNORECASE)
        targets.extend(cves)
        # Hash pattern (MD5, SHA1, SHA256)
        hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', query)
        targets.extend(hashes)
        return list(set(targets))

    def _score_confidence(self, query: str, intent: QueryIntent) -> float:
        """Score confidence in the classification."""
        keywords = self.INTENT_KEYWORDS.get(intent, [])
        matches = sum(1 for kw in keywords if kw in query.lower())
        if matches >= 3:
            return 0.95
        elif matches >= 2:
            return 0.85
        elif matches >= 1:
            return 0.7
        return 0.5

    def get_supported_intents(self) -> list[str]:
        """Return all supported query intents."""
        return [i.value for i in QueryIntent]
