"""EXPORT — Integration with ORION, IDRIS, NEMESIS, SIEM.

Feeds findings into downstream tools. Ed25519 signed.
"""
from __future__ import annotations
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Optional
from raven.models.core import (
    ConversationSession, DarkWebFinding, ExportPayload, IntelFinding, WhisperAlert,
)


class ExportEngine:
    """Export engine — feed intel to the rest of the pipeline."""

    def __init__(self, private_key: Optional[bytes] = None):
        self._private_key = private_key

    def export(
        self, session: ConversationSession,
        findings: list[IntelFinding],
        dark_web: list[DarkWebFinding],
        alerts: list[WhisperAlert] = None,
        format: str = "json",
    ) -> ExportPayload:
        """Export findings as a signed payload."""
        payload = ExportPayload(
            session_id=session.session_id,
            findings=findings,
            dark_web=dark_web,
            alerts=alerts or [],
            target=session.target,
            format=format,
            exported_at=datetime.now(timezone.utc),
        )
        payload.signature = self._sign(payload)
        return payload

    def export_for_orion(self, findings: list[IntelFinding]) -> dict:
        """Export in ORION-compatible format for attack surface enrichment."""
        return {
            "source": "raven",
            "findings": [
                {"target": f.target, "type": f.finding_type, "severity": f.severity.value,
                 "detail": f.detail, "source": f.source.value, "actionable": f.actionable}
                for f in findings if f.actionable
            ],
        }

    def export_for_idris(self, findings: list[IntelFinding]) -> dict:
        """Export in IDRIS-compatible format for identity graph enrichment."""
        return {
            "source": "raven",
            "identities": [
                {"target": f.target, "exposure_type": f.finding_type,
                 "severity": f.severity.value, "detail": f.detail}
                for f in findings if f.finding_type in ("breach_check", "credential_exposure")
            ],
        }

    def export_for_nemesis(self, findings: list[IntelFinding], dark_web: list[DarkWebFinding]) -> dict:
        """Export in NEMESIS-compatible format for reasoning context."""
        return {
            "source": "raven",
            "intel_context": [
                {"type": f.finding_type, "target": f.target, "severity": f.severity.value,
                 "detail": f.detail}
                for f in findings
            ],
            "dark_web_context": [
                {"source": d.source_type.value, "title": d.title, "severity": d.severity.value}
                for d in dark_web
            ],
        }

    def export_for_siem(self, findings: list[IntelFinding]) -> list[dict]:
        """Export as SIEM-ingestible events."""
        return [
            {"event_type": "raven_finding", "source": f.source.value,
             "finding_type": f.finding_type, "target": f.target,
             "severity": f.severity.value, "title": f.title,
             "detail": f.detail, "timestamp": f.discovered_at.isoformat() if f.discovered_at else None}
            for f in findings
        ]

    def verify(self, payload: ExportPayload) -> bool:
        """Verify the signature of an export payload."""
        expected = self._sign(payload)
        return payload.signature == expected

    def _sign(self, payload: ExportPayload) -> str:
        data = json.dumps({
            "session_id": payload.session_id,
            "target": payload.target,
            "finding_count": len(payload.findings),
            "format": payload.format,
        }, sort_keys=True).encode()
        key = self._private_key or b"raven-default-key"
        return hmac.new(key, data, hashlib.sha256).hexdigest()
