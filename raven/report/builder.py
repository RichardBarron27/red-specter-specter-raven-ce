"""RAVEN — Session Report Builder."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from raven.models.core import ConversationSession, IntelFinding, DarkWebFinding, WhisperAlert, RavenResult


class ReportBuilder:
    def build_report(self, result: RavenResult) -> dict:
        report = {
            "report_type": "RAVEN — Threat Intelligence Report",
            "classification": "RESTRICTED",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_findings": len(result.findings),
                "dark_web_findings": len(result.dark_web),
                "alerts": len(result.alerts),
                "duration_ms": result.total_duration_ms,
            },
            "findings_by_severity": self._count_by_severity(result.findings),
            "sources_queried": list({f.source.value for f in result.findings}),
        }
        if result.session:
            report["session"] = {
                "id": result.session.session_id,
                "target": result.session.target,
                "messages": result.session.message_count,
                "queries": result.session.total_queries,
            }
        return report

    def _count_by_severity(self, findings: list[IntelFinding]) -> dict:
        counts = {}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def to_json(self, result: RavenResult) -> str:
        return json.dumps(self.build_report(result), indent=2, default=str)
