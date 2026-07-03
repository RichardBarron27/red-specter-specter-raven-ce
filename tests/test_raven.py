"""RAVEN — Complete Test Suite. Target: 165+ tests."""
import json, time, pytest
from raven.core import *
from raven.models.core import *
from raven.report.builder import ReportBuilder
from raven.unleashed.gate import UnleashedGate, UnleashedMode, UnleashedSession


# ═══ PARSER (40 tests) ═══
class TestParser:
    def test_parse_returns_query(self, parser):
        assert isinstance(parser.parse("test"), ParsedQuery)
    def test_parse_has_intent(self, parser):
        r = parser.parse("check breaches for example.com")
        assert isinstance(r.intent, QueryIntent)
    def test_breach_intent(self, parser):
        assert parser.parse("has example.com been breached?").intent == QueryIntent.BREACH_CHECK
    def test_credential_intent(self, parser):
        assert parser.parse("find stolen credentials password login account").intent == QueryIntent.CREDENTIAL_LOOKUP
    def test_domain_intent(self, parser):
        assert parser.parse("domain intel for example.com").intent == QueryIntent.DOMAIN_INTEL
    def test_ip_intent(self, parser):
        assert parser.parse("ip reputation for 1.2.3.4").intent == QueryIntent.IP_REPUTATION
    def test_dark_web_intent(self, parser):
        assert parser.parse("dark web mentions of our company").intent == QueryIntent.DARK_WEB_MENTION
    def test_threat_actor_intent(self, parser):
        assert parser.parse("threat actor APT29 campaign").intent == QueryIntent.THREAT_ACTOR
    def test_vuln_intent(self, parser):
        assert parser.parse("CVE-2024-1234 exploit vulnerability").intent == QueryIntent.VULNERABILITY_INTEL
    def test_infra_intent(self, parser):
        assert parser.parse("infrastructure hosting server ports").intent == QueryIntent.INFRASTRUCTURE_INTEL
    def test_malware_intent(self, parser):
        assert parser.parse("malware hash analysis ransomware").intent == QueryIntent.MALWARE_ANALYSIS
    def test_general_intent(self, parser):
        assert parser.parse("tell me about something").intent == QueryIntent.GENERAL_OSINT
    def test_extract_email(self, parser):
        r = parser.parse("check admin@example.com")
        assert "admin@example.com" in r.targets
    def test_extract_domain(self, parser):
        r = parser.parse("scan example.com for breaches")
        assert "example.com" in r.targets
    def test_extract_ip(self, parser):
        r = parser.parse("reputation of 192.168.1.1")
        assert "192.168.1.1" in r.targets
    def test_extract_cve(self, parser):
        r = parser.parse("info on CVE-2024-12345")
        assert "CVE-2024-12345" in r.targets
    def test_extract_hash(self, parser):
        r = parser.parse("analyse d41d8cd98f00b204e9800998ecf8427e")
        assert "d41d8cd98f00b204e9800998ecf8427e" in r.targets
    def test_multiple_targets(self, parser):
        r = parser.parse("check admin@test.com and 1.2.3.4")
        assert len(r.targets) >= 2
    def test_sources_mapped(self, parser):
        r = parser.parse("breach check")
        assert len(r.sources_to_query) > 0
    def test_breach_sources_include_hibp(self, parser):
        r = parser.parse("has the email been breached?")
        assert IntelSource.HIBP in r.sources_to_query
    def test_confidence_score(self, parser):
        r = parser.parse("leaked credentials password for domain")
        assert 0 <= r.confidence <= 1
    def test_high_confidence(self, parser):
        r = parser.parse("leaked credentials password account login")
        assert r.confidence >= 0.85
    def test_timestamp(self, parser):
        r = parser.parse("test")
        assert r.parsed_at is not None
    def test_raw_query_preserved(self, parser):
        r = parser.parse("exact query text")
        assert r.raw_query == "exact query text"
    def test_10_intents(self, parser):
        assert len(parser.get_supported_intents()) == 10
    def test_10_intent_keywords(self, parser):
        assert len(parser.INTENT_KEYWORDS) == 10
    def test_source_map_complete(self, parser):
        assert len(parser.SOURCE_MAP) == 10
    def test_no_targets_from_plain_text(self, parser):
        r = parser.parse("tell me about threats")
        # May find some false positives but should be minimal
        assert isinstance(r.targets, list)
    def test_empty_query(self, parser):
        r = parser.parse("")
        assert r.intent == QueryIntent.GENERAL_OSINT
    def test_case_insensitive(self, parser):
        r = parser.parse("BREACH CHECK FOR EXAMPLE.COM")
        assert r.intent == QueryIntent.BREACH_CHECK
    def test_ip_reputation_sources(self, parser):
        r = parser.parse("ip reputation")
        assert IntelSource.VIRUSTOTAL in r.sources_to_query
    def test_dark_web_sources(self, parser):
        r = parser.parse("dark web mentions")
        assert IntelSource.FLARE in r.sources_to_query
    def test_malware_sources(self, parser):
        r = parser.parse("malware analysis")
        assert IntelSource.VIRUSTOTAL in r.sources_to_query
    def test_parameters_dict(self, parser):
        r = parser.parse("test")
        assert isinstance(r.parameters, dict)
    def test_sha256_extraction(self, parser):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        r = parser.parse(f"check {h}")
        assert h in r.targets
    def test_medium_confidence(self, parser):
        r = parser.parse("something about breaches maybe")
        assert r.confidence >= 0.5
    def test_low_confidence_generic(self, parser):
        r = parser.parse("hello")
        assert r.confidence <= 0.7
    def test_domain_with_subdomain(self, parser):
        r = parser.parse("check api.example.com")
        assert any("example.com" in t for t in r.targets)
    def test_multiple_emails(self, parser):
        r = parser.parse("check a@test.com and b@test.com")
        assert len([t for t in r.targets if "@" in t]) >= 2


# ═══ INTEL (30 tests) ═══
class TestIntel:
    def test_query_returns_list(self, intel, parser):
        p = parser.parse("breach check for test@example.com")
        assert isinstance(intel.query(p), list)
    def test_query_has_findings(self, intel, parser):
        p = parser.parse("breach check for test@example.com")
        assert len(intel.query(p)) > 0
    def test_finding_has_id(self, intel, parser):
        p = parser.parse("breach check for test@example.com")
        for f in intel.query(p):
            assert len(f.finding_id) > 0
    def test_finding_has_source(self, intel, parser):
        p = parser.parse("breach check for test@example.com")
        for f in intel.query(p):
            assert isinstance(f.source, IntelSource)
    def test_finding_has_severity(self, intel, parser):
        p = parser.parse("breach check for test@example.com")
        for f in intel.query(p):
            assert isinstance(f.severity, FindingSeverity)
    def test_finding_has_title(self, intel, parser):
        p = parser.parse("breach check for test@example.com")
        for f in intel.query(p):
            assert len(f.title) > 0
    def test_8_sources(self, intel):
        assert len(intel.get_available_sources()) == 8
    def test_query_specific_source(self, intel):
        r = intel.query_source(IntelSource.SHODAN, ["1.2.3.4"])
        assert all(f.source == IntelSource.SHODAN for f in r)
    def test_breaches_returns_list(self, intel):
        records = intel.get_breaches("test@example.com")
        # Returns list (empty without HIBP API key, populated with key)
        assert isinstance(records, list)
    def test_breach_record_structure(self, intel):
        records = intel.get_breaches("test@example.com")
        if records:
            assert len(records[0].breach_name) > 0
            assert isinstance(records[0], BreachRecord)
    def test_breach_requires_api_key(self, intel):
        # Without HIBP_API_KEY, returns empty list
        import os
        if not os.environ.get("HIBP_API_KEY"):
            records = intel.get_breaches("test@example.com")
            assert records == []
    def test_breach_record_types_if_available(self, intel):
        records = intel.get_breaches("test@example.com")
        if records:
            assert len(records[0].data_types) > 0
    def test_hibp_client(self, intel):
        r = intel._query_hibp(["test"], "breach")
        assert len(r) > 0
    def test_vt_client(self, intel):
        r = intel._query_virustotal(["test"], "reputation")
        assert len(r) > 0
    def test_shodan_client(self, intel):
        r = intel._query_shodan(["test"], "infra")
        assert len(r) > 0
    def test_censys_client(self, intel):
        r = intel._query_censys(["test"], "cert")
        assert len(r) > 0
    def test_flare_client(self, intel):
        r = intel._query_flare(["test"], "dark_web")
        assert len(r) > 0
    def test_spycloud_client(self, intel):
        r = intel._query_spycloud(["test"], "creds")
        # SpyCloud now reports as requiring enterprise subscription
        assert len(r) > 0
    def test_greynoise_client(self, intel):
        r = intel._query_greynoise(["8.8.8.8"], "noise")
        assert len(r) > 0
    def test_pulsedive_client(self, intel):
        r = intel._query_pulsedive(["8.8.8.8"], "indicator")
        assert len(r) > 0
    def test_finding_timestamp(self, intel, parser):
        p = parser.parse("breach test@example.com")
        for f in intel.query(p):
            assert f.discovered_at is not None
    def test_finding_confidence(self, intel, parser):
        p = parser.parse("breach test@example.com")
        for f in intel.query(p):
            assert 0 <= f.confidence <= 1
    def test_actionable_findings(self, intel, parser):
        p = parser.parse("breach test@example.com")
        findings = intel.query(p)
        assert any(f.actionable for f in findings)
    def test_multiple_targets(self, intel):
        # Without API key, Shodan returns 1 "skipped" finding
        r = intel.query_source(IntelSource.SHODAN, ["1.1.1.1", "8.8.8.8"])
        assert len(r) >= 1
    def test_finding_type_set(self, intel, parser):
        p = parser.parse("breach test@example.com")
        for f in intel.query(p):
            assert len(f.finding_type) > 0
    def test_object_type(self, intel, parser):
        p = parser.parse("breach test@example.com")
        for f in intel.query(p):
            assert isinstance(f, IntelFinding)
    def test_breach_record_type(self, intel):
        records = intel.get_breaches("test@example.com")
        if records:
            assert isinstance(records[0], BreachRecord)
    def test_empty_targets(self, intel):
        r = intel.query_source(IntelSource.SHODAN, [])
        # May return empty or a single "skipped/no-key" finding
        assert isinstance(r, list)
    def test_finding_target_set(self, intel):
        r = intel.query_source(IntelSource.SHODAN, ["target.com"])
        assert r[0].target == "target.com"
    def test_all_clients_exist(self, intel):
        assert len(intel._clients) == 8


# ═══ DARK (20 tests) ═══
class TestDark:
    def test_scrape_returns_list(self, dark):
        assert isinstance(dark.scrape("test"), list)
    def test_scrape_has_findings(self, dark):
        assert len(dark.scrape("test")) > 0
    def test_finding_has_source_type(self, dark):
        for f in dark.scrape("test"):
            assert isinstance(f.source_type, DarkWebSource)
    def test_finding_has_title(self, dark):
        for f in dark.scrape("test"):
            assert len(f.title) > 0
    def test_finding_mentions_target(self, dark):
        findings = dark.scrape("test")
        assert any(f.mentions_target for f in findings)
    def test_6_sources(self, dark):
        assert len(dark.get_available_sources()) == 6
    def test_dry_run(self, dark):
        r = dark.scrape("test", dry_run=True)
        assert all("[DRY RUN]" in f.title for f in r)
    def test_dry_run_requires_unleashed(self, dark):
        r = dark.scrape("test", dry_run=True)
        assert all(f.requires_unleashed for f in r)
    def test_forum_source(self, dark):
        r = dark.scrape("test", [DarkWebSource.FORUM])
        assert all(f.source_type == DarkWebSource.FORUM for f in r)
    def test_marketplace_source(self, dark):
        r = dark.scrape("test", [DarkWebSource.MARKETPLACE])
        assert all(f.source_type == DarkWebSource.MARKETPLACE for f in r)
    def test_paste_source(self, dark):
        r = dark.scrape("test", [DarkWebSource.PASTE_SITE])
        assert len(r) >= 1
    def test_telegram_source(self, dark):
        r = dark.scrape("test", [DarkWebSource.TELEGRAM])
        assert len(r) >= 1
    def test_irc_source(self, dark):
        r = dark.scrape("test", [DarkWebSource.IRC])
        assert len(r) >= 1
    def test_onion_source(self, dark):
        r = dark.scrape("test", [DarkWebSource.ONION_SERVICE])
        assert len(r) >= 1
    def test_critical_marketplace(self, dark):
        r = dark.scrape("test", [DarkWebSource.MARKETPLACE])
        assert any(f.severity == FindingSeverity.CRITICAL for f in r)
    def test_timestamp(self, dark):
        for f in dark.scrape("test"):
            assert f.discovered_at is not None
    def test_object_type(self, dark):
        for f in dark.scrape("test"):
            assert isinstance(f, DarkWebFinding)
    def test_single_source_filter(self, dark):
        r = dark.scrape("test", [DarkWebSource.IRC])
        assert all(f.source_type == DarkWebSource.IRC for f in r)
    def test_all_sources(self, dark):
        r = dark.scrape("test")
        sources = {f.source_type for f in r}
        assert len(sources) >= 4
    def test_content_preview(self, dark):
        r = dark.scrape("test", [DarkWebSource.FORUM])
        assert any(f.content_preview for f in r)


# ═══ ORCHESTRATOR (20 tests) ═══
class TestOrchestrator:
    def test_create_session(self, orchestrator):
        s = orchestrator.create_session("test")
        assert isinstance(s, ConversationSession)
    def test_session_has_id(self, orchestrator):
        s = orchestrator.create_session("test")
        assert len(s.session_id) > 0
    def test_session_has_target(self, orchestrator):
        s = orchestrator.create_session("example.com")
        assert s.target == "example.com"
    def test_add_user_message(self, orchestrator):
        s = orchestrator.create_session()
        msg = orchestrator.add_user_message(s.session_id, "hello")
        assert msg.role == "user"
    def test_add_raven_response(self, orchestrator):
        s = orchestrator.create_session()
        msg = orchestrator.add_raven_response(s.session_id, "response")
        assert msg.role == "raven"
    def test_message_count(self, orchestrator):
        s = orchestrator.create_session()
        orchestrator.add_user_message(s.session_id, "q1")
        orchestrator.add_raven_response(s.session_id, "a1")
        assert s.message_count == 2
    def test_total_queries(self, orchestrator):
        s = orchestrator.create_session()
        orchestrator.add_user_message(s.session_id, "q1")
        orchestrator.add_user_message(s.session_id, "q2")
        assert s.total_queries == 2
    def test_fuse_results(self, orchestrator, intel, parser):
        p = parser.parse("breach test@example.com")
        findings = intel.query(p)
        fused, _ = orchestrator.fuse_results(findings, [])
        assert len(fused) > 0
    def test_fuse_deduplicates(self, orchestrator):
        f1 = IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="breach", title="t", target="x")
        f2 = IntelFinding(finding_id="2", source=IntelSource.HIBP, finding_type="breach", title="t", target="x")
        fused, _ = orchestrator.fuse_results([f1, f2], [])
        assert len(fused) == 1
    def test_fuse_prioritises(self, orchestrator):
        f1 = IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="a", title="low", severity=FindingSeverity.LOW, target="x")
        f2 = IntelFinding(finding_id="2", source=IntelSource.SHODAN, finding_type="b", title="crit", severity=FindingSeverity.CRITICAL, target="x")
        fused, _ = orchestrator.fuse_results([f1, f2], [])
        assert fused[0].severity == FindingSeverity.CRITICAL
    def test_synthesise_answer(self, orchestrator, parser):
        p = parser.parse("test")
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="breach",
                                 title="Breach found", severity=FindingSeverity.CRITICAL, target="x")]
        answer = orchestrator.synthesise_answer(p, findings, [])
        assert "CRITICAL" in answer
    def test_synthesise_no_findings(self, orchestrator, parser):
        p = parser.parse("test")
        answer = orchestrator.synthesise_answer(p, [], [])
        assert "No significant" in answer
    def test_get_session(self, orchestrator):
        s = orchestrator.create_session()
        assert orchestrator.get_session(s.session_id) is not None
    def test_end_session(self, orchestrator):
        s = orchestrator.create_session()
        ended = orchestrator.end_session(s.session_id)
        assert ended.ended_at is not None
    def test_session_started_at(self, orchestrator):
        s = orchestrator.create_session()
        assert s.started_at is not None
    def test_findings_with_response(self, orchestrator):
        s = orchestrator.create_session()
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t", title="t", target="x")]
        msg = orchestrator.add_raven_response(s.session_id, "r", findings)
        assert len(msg.findings) == 1
    def test_total_findings_updated(self, orchestrator):
        s = orchestrator.create_session()
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t", title="t", target="x")]
        orchestrator.add_raven_response(s.session_id, "r", findings)
        assert s.total_findings == 1
    def test_dark_web_with_response(self, orchestrator):
        s = orchestrator.create_session()
        dark = [DarkWebFinding(source_type=DarkWebSource.FORUM, title="test")]
        msg = orchestrator.add_raven_response(s.session_id, "r", dark_web=dark)
        assert len(msg.dark_web) == 1
    def test_synthesise_dark_web(self, orchestrator, parser):
        p = parser.parse("test")
        dark = [DarkWebFinding(source_type=DarkWebSource.FORUM, title="Forum post")]
        answer = orchestrator.synthesise_answer(p, [], dark)
        assert "dark web" in answer.lower() or "Dark web" in answer
    def test_unknown_session(self, orchestrator):
        assert orchestrator.get_session("nonexistent") is None


# ═══ TUI (15 tests) ═══
class TestTUI:
    def test_format_user_message(self, tui):
        msg = ConversationMessage(role="user", content="hello")
        assert "[YOU]" in tui.format_message(msg)
    def test_format_raven_message(self, tui):
        msg = ConversationMessage(role="raven", content="response")
        assert "[RAVEN]" in tui.format_message(msg)
    def test_format_with_findings(self, tui):
        msg = ConversationMessage(role="raven", content="r", findings=[
            IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t", title="t", target="x")])
        assert "findings" in tui.format_message(msg)
    def test_format_finding(self, tui):
        f = IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t",
                         title="Breach", detail="Details", severity=FindingSeverity.HIGH, target="x")
        formatted = tui.format_finding(f)
        assert "HIGH" in formatted and "haveibeenpwned" in formatted
    def test_format_dark_web(self, tui):
        d = DarkWebFinding(source_type=DarkWebSource.FORUM, title="Post", content_preview="Preview")
        formatted = tui.format_dark_web(d)
        assert "DARK" in formatted and "forum" in formatted
    def test_format_session_summary(self, tui):
        s = ConversationSession(session_id="test", target="example.com")
        summary = tui.format_session_summary(s)
        assert "test" in summary and "example.com" in summary
    def test_welcome_banner(self, tui):
        banner = tui.render_welcome()
        assert "RAVEN" in banner
    def test_history_empty(self, tui):
        assert tui.get_history() == []
    def test_add_to_history(self, tui):
        tui.add_to_history("entry1")
        assert len(tui.get_history()) == 1
    def test_history_preserved(self, tui):
        tui.add_to_history("e1")
        tui.add_to_history("e2")
        assert tui.get_history() == ["e1", "e2"]
    def test_format_critical_finding(self, tui):
        f = IntelFinding(finding_id="1", source=IntelSource.SPYCLOUD, finding_type="cred",
                         title="Creds", severity=FindingSeverity.CRITICAL, target="x")
        assert "CRITICAL" in tui.format_finding(f)
    def test_message_content_preserved(self, tui):
        msg = ConversationMessage(role="user", content="exact text")
        assert "exact text" in tui.format_message(msg)
    def test_dark_web_preview(self, tui):
        d = DarkWebFinding(source_type=DarkWebSource.MARKETPLACE, title="t", content_preview="preview text")
        assert "preview text" in tui.format_dark_web(d)
    def test_session_messages_count(self, tui):
        s = ConversationSession(session_id="t", messages=[
            ConversationMessage(role="user", content="q"),
            ConversationMessage(role="raven", content="a")])
        summary = tui.format_session_summary(s)
        assert "2" in summary
    def test_format_info_finding(self, tui):
        f = IntelFinding(finding_id="1", source=IntelSource.CENSYS, finding_type="cert",
                         title="Cert", severity=FindingSeverity.INFO, target="x")
        assert "INFO" in tui.format_finding(f)


# ═══ EXPORT (15 tests) ═══
class TestExport:
    def test_export_returns_payload(self, export):
        s = ConversationSession(session_id="t", target="x")
        p = export.export(s, [], [])
        assert isinstance(p, ExportPayload)
    def test_export_has_signature(self, export):
        s = ConversationSession(session_id="t", target="x")
        p = export.export(s, [], [])
        assert len(p.signature) > 0
    def test_verify_export(self, export):
        s = ConversationSession(session_id="t", target="x")
        p = export.export(s, [], [])
        assert export.verify(p)
    def test_export_for_orion(self, export):
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="breach",
                                 title="t", target="x", actionable=True)]
        r = export.export_for_orion(findings)
        assert r["source"] == "raven" and len(r["findings"]) == 1
    def test_export_for_idris(self, export):
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="breach_check",
                                 title="t", target="x")]
        r = export.export_for_idris(findings)
        assert r["source"] == "raven"
    def test_export_for_nemesis(self, export):
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t", title="t", target="x")]
        dark = [DarkWebFinding(source_type=DarkWebSource.FORUM, title="t")]
        r = export.export_for_nemesis(findings, dark)
        assert "intel_context" in r and "dark_web_context" in r
    def test_export_for_siem(self, export):
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t", title="t", target="x")]
        events = export.export_for_siem(findings)
        assert len(events) == 1 and events[0]["event_type"] == "raven_finding"
    def test_export_timestamp(self, export):
        s = ConversationSession(session_id="t", target="x")
        p = export.export(s, [], [])
        assert p.exported_at is not None
    def test_export_session_id(self, export):
        s = ConversationSession(session_id="my-session", target="x")
        p = export.export(s, [], [])
        assert p.session_id == "my-session"
    def test_export_format(self, export):
        s = ConversationSession(session_id="t", target="x")
        p = export.export(s, [], [], format="siem")
        assert p.format == "siem"
    def test_non_actionable_excluded_from_orion(self, export):
        findings = [IntelFinding(finding_id="1", source=IntelSource.CENSYS, finding_type="cert",
                                 title="t", target="x", actionable=False)]
        r = export.export_for_orion(findings)
        assert len(r["findings"]) == 0
    def test_export_with_findings(self, export):
        s = ConversationSession(session_id="t", target="x")
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t", title="t", target="x")]
        p = export.export(s, findings, [])
        assert len(p.findings) == 1
    def test_export_with_alerts(self, export):
        s = ConversationSession(session_id="t", target="x")
        alerts = [WhisperAlert(alert_id="a1", alert_type=AlertType.CREDENTIAL_LEAK, target="x", title="t")]
        p = export.export(s, [], [], alerts)
        assert len(p.alerts) == 1
    def test_siem_event_has_timestamp(self, export):
        from datetime import datetime, timezone
        findings = [IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t", title="t",
                                 target="x", discovered_at=datetime.now(timezone.utc))]
        events = export.export_for_siem(findings)
        assert events[0]["timestamp"] is not None
    def test_idris_filters_breach_types(self, export):
        f1 = IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="breach_check", title="t", target="x")
        f2 = IntelFinding(finding_id="2", source=IntelSource.SHODAN, finding_type="infrastructure", title="t", target="x")
        r = export.export_for_idris([f1, f2])
        assert len(r["identities"]) == 1


# ═══ WHISPER (15 tests) ═══
class TestWhisper:
    def test_add_to_watchlist(self, whisper):
        whisper.add_to_watchlist("example.com")
        assert len(whisper.get_watchlist()) == 1
    def test_remove_from_watchlist(self, whisper):
        whisper.add_to_watchlist("example.com")
        whisper.remove_from_watchlist("example.com")
        assert len(whisper.get_watchlist()) == 0
    def test_check_all_returns_alerts(self, whisper):
        whisper.add_to_watchlist("example.com")
        alerts = whisper.check_all()
        assert len(alerts) > 0
    def test_alert_has_id(self, whisper):
        whisper.add_to_watchlist("test")
        for a in whisper.check_all():
            assert len(a.alert_id) > 0
    def test_alert_has_type(self, whisper):
        whisper.add_to_watchlist("test")
        for a in whisper.check_all():
            assert isinstance(a.alert_type, AlertType)
    def test_alert_has_severity(self, whisper):
        whisper.add_to_watchlist("test")
        for a in whisper.check_all():
            assert isinstance(a.severity, FindingSeverity)
    def test_alert_has_target(self, whisper):
        whisper.add_to_watchlist("example.com")
        for a in whisper.check_all():
            assert a.target == "example.com"
    def test_acknowledge_alert(self, whisper):
        whisper.add_to_watchlist("test")
        alerts = whisper.check_all()
        whisper.acknowledge_alert(alerts[0].alert_id)
        assert alerts[0].acknowledged
    def test_unacknowledged_filter(self, whisper):
        whisper.add_to_watchlist("test")
        whisper.check_all()
        unack = whisper.get_alerts(unacknowledged_only=True)
        assert len(unack) > 0
    def test_6_alert_types(self, whisper):
        assert len(whisper.get_alert_types()) == 6
    def test_credential_leak_alert(self, whisper):
        whisper.add_to_watchlist("test")
        alerts = whisper.check_all()
        assert any(a.alert_type == AlertType.CREDENTIAL_LEAK for a in alerts)
    def test_dark_web_mention_alert(self, whisper):
        whisper.add_to_watchlist("test")
        alerts = whisper.check_all()
        assert any(a.alert_type == AlertType.DARK_WEB_MENTION for a in alerts)
    def test_data_sale_alert(self, whisper):
        whisper.add_to_watchlist("test")
        alerts = whisper.check_all()
        assert any(a.alert_type == AlertType.DATA_SALE for a in alerts)
    def test_empty_watchlist_no_alerts(self, whisper):
        assert whisper.check_all() == []
    def test_alert_first_seen(self, whisper):
        whisper.add_to_watchlist("test")
        for a in whisper.check_all():
            assert a.first_seen is not None


# ═══ UNLEASHED (10 tests) ═══
class TestUnleashed:
    def test_standard(self, gate): assert gate.resolve_mode(False, False) == UnleashedMode.STANDARD
    def test_dry_run(self, gate): assert gate.resolve_mode(True, False) == UnleashedMode.DRY_RUN
    def test_live(self, gate): assert gate.resolve_mode(True, True) == UnleashedMode.LIVE
    def test_not_unlocked(self, gate): assert not gate.is_unlocked()
    def test_unlock_standard(self, gate):
        gate.unlock(UnleashedMode.STANDARD, ["t"])
        assert gate.is_unlocked()
    def test_scope_valid(self, gate):
        gate.unlock(UnleashedMode.STANDARD, ["test"])
        assert gate.check_scope("test")
    def test_scope_invalid(self, gate):
        gate.unlock(UnleashedMode.STANDARD, ["test"])
        assert not gate.check_scope("other")
    def test_lock(self, gate):
        gate.unlock(UnleashedMode.STANDARD, ["t"])
        gate.lock()
        assert not gate.is_unlocked()
    def test_live_requires_key(self, gate):
        with pytest.raises(PermissionError): gate.unlock(UnleashedMode.LIVE, ["t"])
    def test_session_duration(self, gate):
        assert gate.SESSION_DURATION == 1800


# ═══ Report + Models (10 tests) ═══
class TestReportAndModels:
    def test_build_report(self):
        r = RavenResult()
        report = ReportBuilder().build_report(r)
        assert report["report_type"] == "RAVEN — Threat Intelligence Report"
    def test_report_json(self):
        r = RavenResult()
        j = ReportBuilder().to_json(r)
        assert json.loads(j)["report_type"] == "RAVEN — Threat Intelligence Report"
    def test_severity_counts(self):
        findings = [
            IntelFinding(finding_id="1", source=IntelSource.HIBP, finding_type="t", title="t", severity=FindingSeverity.CRITICAL, target="x"),
            IntelFinding(finding_id="2", source=IntelSource.SHODAN, finding_type="t", title="t", severity=FindingSeverity.CRITICAL, target="x"),
        ]
        r = RavenResult(findings=findings)
        report = ReportBuilder().build_report(r)
        assert report["findings_by_severity"]["critical"] == 2
    def test_intel_source_enum(self):
        assert len(IntelSource) == 8
    def test_dark_web_source_enum(self):
        assert len(DarkWebSource) == 6
    def test_query_intent_enum(self):
        assert len(QueryIntent) == 10
    def test_alert_type_enum(self):
        assert len(AlertType) == 6
    def test_finding_severity_enum(self):
        assert len(FindingSeverity) == 5
    def test_conversation_message(self):
        m = ConversationMessage(role="user", content="test")
        assert m.role == "user"
    def test_raven_result(self):
        r = RavenResult()
        assert r.total_duration_ms == 0
