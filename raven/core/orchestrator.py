"""ORCHESTRATOR — Result Fusion, Deduplication, Context Management.

Combines results from all sources, enriches with ORION data,
maintains conversation context.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from raven.models.core import (
    ConversationMessage, ConversationSession, DarkWebFinding,
    FindingSeverity, IntelFinding, ParsedQuery,
)


class OrchestratorEngine:
    """Result orchestrator — fuse, deduplicate, contextualise."""

    def __init__(self):
        self._sessions: dict[str, ConversationSession] = {}

    def create_session(self, target: str = "") -> ConversationSession:
        """Create a new conversation session."""
        session = ConversationSession(
            session_id=uuid.uuid4().hex[:12],
            target=target,
            started_at=datetime.now(timezone.utc),
        )
        self._sessions[session.session_id] = session
        return session

    def add_user_message(self, session_id: str, content: str) -> ConversationMessage:
        """Add a user message to the session."""
        msg = ConversationMessage(
            role="user", content=content, timestamp=datetime.now(timezone.utc),
        )
        session = self._sessions.get(session_id)
        if session:
            session.messages.append(msg)
            session.total_queries += 1
        return msg

    def add_raven_response(
        self, session_id: str, content: str,
        findings: list[IntelFinding] = None,
        dark_web: list[DarkWebFinding] = None,
    ) -> ConversationMessage:
        """Add a RAVEN response to the session."""
        msg = ConversationMessage(
            role="raven", content=content,
            findings=findings or [], dark_web=dark_web or [],
            timestamp=datetime.now(timezone.utc),
        )
        session = self._sessions.get(session_id)
        if session:
            session.messages.append(msg)
            session.total_findings += len(msg.findings) + len(msg.dark_web)
        return msg

    def fuse_results(
        self, intel_findings: list[IntelFinding],
        dark_web_findings: list[DarkWebFinding],
    ) -> tuple[list[IntelFinding], list[DarkWebFinding]]:
        """Fuse and deduplicate results from all sources."""
        deduped_intel = self._deduplicate_intel(intel_findings)
        deduped_dark = self._deduplicate_dark(dark_web_findings)
        deduped_intel = self._prioritise_intel(deduped_intel)
        return deduped_intel, deduped_dark

    def synthesise_answer(
        self, query: ParsedQuery,
        findings: list[IntelFinding],
        dark_web: list[DarkWebFinding],
    ) -> str:
        """Synthesise a natural language answer from findings."""
        parts = []
        if findings:
            critical = [f for f in findings if f.severity == FindingSeverity.CRITICAL]
            high = [f for f in findings if f.severity == FindingSeverity.HIGH]
            if critical:
                parts.append(f"CRITICAL: {len(critical)} critical findings.")
                for f in critical[:3]:
                    parts.append(f"  - [{f.source.value}] {f.title}")
            if high:
                parts.append(f"HIGH: {len(high)} high-risk findings.")
                for f in high[:3]:
                    parts.append(f"  - [{f.source.value}] {f.title}")
            remaining = len(findings) - len(critical) - len(high)
            if remaining > 0:
                parts.append(f"Plus {remaining} additional findings at medium/low severity.")
        if dark_web:
            parts.append(f"Dark web: {len(dark_web)} mentions found.")
            for d in dark_web[:2]:
                parts.append(f"  - [{d.source_type.value}] {d.title}")
        if not parts:
            parts.append(f"No significant findings for query: {query.raw_query}")
        return "\n".join(parts)

    def get_session(self, session_id: str) -> Optional[ConversationSession]:
        return self._sessions.get(session_id)

    def end_session(self, session_id: str) -> Optional[ConversationSession]:
        session = self._sessions.get(session_id)
        if session:
            session.ended_at = datetime.now(timezone.utc)
        return session

    def _deduplicate_intel(self, findings: list[IntelFinding]) -> list[IntelFinding]:
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.source.value}:{f.target}:{f.finding_type}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _deduplicate_dark(self, findings: list[DarkWebFinding]) -> list[DarkWebFinding]:
        seen = set()
        unique = []
        for f in findings:
            key = f"{f.source_type.value}:{f.title}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _prioritise_intel(self, findings: list[IntelFinding]) -> list[IntelFinding]:
        order = {FindingSeverity.CRITICAL: 0, FindingSeverity.HIGH: 1,
                 FindingSeverity.MEDIUM: 2, FindingSeverity.LOW: 3, FindingSeverity.INFO: 4}
        return sorted(findings, key=lambda f: (order.get(f.severity, 5), -f.confidence))
