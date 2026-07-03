"""TUI — Conversational Terminal Interface.

Chat-style terminal UI. In production uses textual.
Framework layer provides the rendering logic.
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional
from raven.models.core import ConversationMessage, ConversationSession, IntelFinding, DarkWebFinding


class TUIEngine:
    """Terminal UI engine — renders conversation and findings."""

    def __init__(self):
        self._history: list[str] = []

    def format_message(self, msg: ConversationMessage) -> str:
        """Format a conversation message for display."""
        if msg.role == "user":
            return f"\n  [YOU] {msg.content}"
        parts = [f"\n  [RAVEN] {msg.content}"]
        if msg.findings:
            parts.append(f"  ({len(msg.findings)} findings attached)")
        if msg.dark_web:
            parts.append(f"  ({len(msg.dark_web)} dark web results)")
        return "\n".join(parts)

    def format_finding(self, finding: IntelFinding) -> str:
        """Format a single finding for display."""
        sev = finding.severity.value.upper()
        return f"  [{sev}] [{finding.source.value}] {finding.title}\n    {finding.detail}"

    def format_dark_web(self, finding: DarkWebFinding) -> str:
        """Format a dark web finding for display."""
        return f"  [DARK] [{finding.source_type.value}] {finding.title}\n    {finding.content_preview}"

    def format_session_summary(self, session: ConversationSession) -> str:
        """Format a session summary."""
        return (
            f"\n  Session: {session.session_id}\n"
            f"  Target: {session.target}\n"
            f"  Messages: {session.message_count}\n"
            f"  Findings: {session.total_findings}\n"
            f"  Queries: {session.total_queries}\n"
        )

    def render_welcome(self) -> str:
        """Render the welcome banner."""
        return (
            "\n  ╔══════════════════════════════════════════╗\n"
            "  ║  RAVEN — Threat Intelligence Assistant   ║\n"
            "  ╚══════════════════════════════════════════╝\n"
            "\n  Ask me anything about a target. I query\n"
            "  breach databases, dark web sources, and\n"
            "  threat intelligence APIs.\n"
            "\n  Type 'exit' to end the session.\n"
        )

    def add_to_history(self, entry: str):
        self._history.append(entry)

    def get_history(self) -> list[str]:
        return self._history.copy()
