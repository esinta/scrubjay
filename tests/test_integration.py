"""Integration tests: full round-trip sanitize → restore for all profiles."""

import json
import os

from scrubjay.core.session import SanitizeSession
from scrubjay.core.types import FieldType, ScrubRule, Tier

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def _load_fixture(name: str) -> list[dict]:
    with open(os.path.join(FIXTURES_DIR, name)) as f:
        return json.load(f)


# ── Okta ──


class TestOktaIntegration:
    def test_sanitize_and_restore_round_trip(self):
        events = _load_fixture("okta_sample.json")
        session = SanitizeSession(profiles=["okta"], seed="okta-test")
        result = session.sanitize(events)

        sanitized = result.sanitized_data
        assert len(sanitized) == len(events)

        # Verify actor fields are tokenized
        for i, evt in enumerate(sanitized):
            orig = events[i]
            if orig.get("actor", {}).get("displayName"):
                assert evt["actor"]["displayName"] != orig["actor"]["displayName"]
                assert evt["actor"]["displayName"].startswith("PERSON-")
            if orig.get("actor", {}).get("alternateId"):
                assert evt["actor"]["alternateId"] != orig["actor"]["alternateId"]

        # Restore text round-trip
        sanitized_json = json.dumps(sanitized)
        restored_json = session.restore(sanitized_json)
        restored = json.loads(restored_json)

        for i, evt in enumerate(restored):
            orig = events[i]
            if orig.get("actor", {}).get("displayName"):
                assert evt["actor"]["displayName"] == orig["actor"]["displayName"]

    def test_entity_linking_across_records(self):
        events = _load_fixture("okta_sample.json")
        session = SanitizeSession(profiles=["okta"], seed="link-test")
        result = session.sanitize(events)

        # Find events with same actor — same actor should get same token
        actor_tokens: dict[str, str] = {}
        for i, evt in enumerate(result.sanitized_data):
            orig_actor = events[i].get("actor", {}).get("displayName")
            if orig_actor:
                token = evt["actor"]["displayName"]
                if orig_actor in actor_tokens:
                    assert actor_tokens[orig_actor] == token
                else:
                    actor_tokens[orig_actor] = token

    def test_tier_filtering(self):
        events = _load_fixture("okta_sample.json")[:3]
        session = SanitizeSession(
            profiles=["okta"], tier=Tier.ALWAYS, seed="tier-test"
        )
        result = session.sanitize(events)

        # Tier ALWAYS: only tier-1 fields should be scrubbed
        # client.userAgent.rawUserAgent is tier 2, should NOT be scrubbed
        for i, evt in enumerate(result.sanitized_data):
            orig = events[i]
            ua = orig.get("client", {}).get("userAgent", {}).get("rawUserAgent")
            if ua:
                assert evt["client"]["userAgent"]["rawUserAgent"] == ua

    def test_stats_populated(self):
        events = _load_fixture("okta_sample.json")[:5]
        session = SanitizeSession(profiles=["okta"], seed="stats-test")
        result = session.sanitize(events)
        assert len(result.stats) > 0
        assert session.cache_size > 0


# ── Corelight ──


class TestCorelightIntegration:
    def test_conn_log_passthrough(self):
        """Corelight conn.log fields are all PASSTHROUGH — nothing scrubbed."""
        events = _load_fixture("corelight_conn.json")
        session = SanitizeSession(profiles=["corelight"], seed="conn-test")
        result = session.sanitize(events)

        # conn.log has no sensitive fields, should be unchanged
        for i, evt in enumerate(result.sanitized_data):
            assert evt == events[i]

    def test_dns_query_scrubbed(self):
        """DNS query field should be tokenized as HOSTNAME."""
        events = _load_fixture("corelight_dns.json")
        session = SanitizeSession(profiles=["corelight"], seed="dns-test")
        result = session.sanitize(events)

        for i, evt in enumerate(result.sanitized_data):
            orig = events[i]
            if orig.get("query"):
                assert evt["query"] != orig["query"]
                assert evt["query"].startswith("HOST-")

    def test_dns_restore_round_trip(self):
        events = _load_fixture("corelight_dns.json")
        session = SanitizeSession(profiles=["corelight"], seed="dns-rt")
        result = session.sanitize(events)

        sanitized_json = json.dumps(result.sanitized_data)
        restored_json = session.restore(sanitized_json)
        restored = json.loads(restored_json)

        for i, evt in enumerate(restored):
            orig = events[i]
            if orig.get("query"):
                assert evt["query"] == orig["query"]


# ── Proofpoint ──


class TestProofpointIntegration:
    def test_email_fields_scrubbed(self):
        events = _load_fixture("proofpoint_sample.json")
        session = SanitizeSession(profiles=["proofpoint"], seed="pp-test")
        result = session.sanitize(events)

        for i, evt in enumerate(result.sanitized_data):
            orig = events[i]
            # sender should be scrubbed
            assert evt["sender"] != orig["sender"]
            # recipient should be scrubbed
            assert evt["recipient"] != orig["recipient"]
            # subject should be scrubbed
            if orig.get("subject"):
                assert evt["subject"] != orig["subject"]

    def test_proofpoint_restore_round_trip(self):
        events = _load_fixture("proofpoint_sample.json")
        session = SanitizeSession(profiles=["proofpoint"], seed="pp-rt")
        result = session.sanitize(events)

        sanitized_json = json.dumps(result.sanitized_data)
        restored_json = session.restore(sanitized_json)
        restored = json.loads(restored_json)

        for i, evt in enumerate(restored):
            orig = events[i]
            assert evt["sender"] == orig["sender"]
            assert evt["recipient"] == orig["recipient"]

    def test_attachment_filenames_scrubbed(self):
        events = _load_fixture("proofpoint_sample.json")
        session = SanitizeSession(profiles=["proofpoint"], seed="pp-att")
        result = session.sanitize(events)

        for i, evt in enumerate(result.sanitized_data):
            orig = events[i]
            for j, part in enumerate(orig.get("messageParts", [])):
                if part.get("filename"):
                    scrubbed_fn = evt["messageParts"][j]["filename"]
                    assert scrubbed_fn != part["filename"]


# ── Esinta ──


class TestEsintaIntegration:
    def test_sensitive_fields_scrubbed(self):
        events = _load_fixture("esinta_sample.json")
        session = SanitizeSession(profiles=["esinta"], seed="esinta-test")
        result = session.sanitize(events)

        for i, evt in enumerate(result.sanitized_data):
            orig = events[i]
            # username → USER-xxxx
            assert evt["username"] != orig["username"]
            assert evt["username"].startswith("USER-")
            # hostname → HOST-xxxx
            assert evt["hostname"] != orig["hostname"]
            assert evt["hostname"].startswith("HOST-")
            # domain → DOMAIN-xxxx
            assert evt["domain"] != orig["domain"]

    def test_freetext_command_line_scrubbed(self):
        """FREETEXT command_line should have sub-entities replaced."""
        events = _load_fixture("esinta_sample.json")
        session = SanitizeSession(profiles=["esinta"], seed="esinta-ft")
        result = session.sanitize(events)

        # Event 3: command_line has C:\Users\mchen\... username path
        evt3 = result.sanitized_data[3]
        cmd = evt3["command_line"]
        # Should NOT contain the original username
        assert "mchen" not in cmd
        # The command_line should still have the cmd.exe structure
        assert "cmd.exe" in cmd

    def test_passthrough_fields_unchanged(self):
        events = _load_fixture("esinta_sample.json")
        session = SanitizeSession(profiles=["esinta"], seed="esinta-pt")
        result = session.sanitize(events)

        for i, evt in enumerate(result.sanitized_data):
            orig = events[i]
            assert evt["event_id"] == orig["event_id"]
            assert evt["process_name"] == orig["process_name"]
            assert evt["file_hash"] == orig["file_hash"]
            assert evt["process_id"] == orig["process_id"]

    def test_esinta_restore_round_trip(self):
        events = _load_fixture("esinta_sample.json")
        session = SanitizeSession(profiles=["esinta"], seed="esinta-rt")
        result = session.sanitize(events)

        # Use restore_data for structured restoration
        restored = session.restore_data(result.sanitized_data)

        for i, evt in enumerate(restored):
            orig = events[i]
            assert evt["username"] == orig["username"]
            assert evt["hostname"] == orig["hostname"]
            assert evt["domain"] == orig["domain"]


# ── Multi-profile ──


class TestMultiProfileIntegration:
    def test_two_profiles_together(self):
        """Using multiple profiles simultaneously."""
        okta_events = _load_fixture("okta_sample.json")[:2]
        session = SanitizeSession(
            profiles=["okta", "esinta"], seed="multi-test"
        )
        result = session.sanitize(okta_events)
        assert len(result.sanitized_data) == 2

    def test_custom_rules_with_profile(self):
        """Custom rules on top of a profile."""
        events = _load_fixture("esinta_sample.json")[:2]
        custom = [
            ScrubRule("ip_address", FieldType.HOSTNAME, Tier.ALWAYS,
                      description="Scrub IPs as hostnames"),
        ]
        session = SanitizeSession(
            profiles=["esinta"], custom_rules=custom, seed="custom-test"
        )
        result = session.sanitize(events)
        for evt in result.sanitized_data:
            # ip_address should now be scrubbed
            assert evt["ip_address"] != events[0]["ip_address"]


# ── Context manager ──


class TestSessionContextManager:
    def test_context_manager_clears_cache(self):
        events = _load_fixture("esinta_sample.json")[:2]
        with SanitizeSession(
            profiles=["esinta"], seed="ctx-test"
        ) as session:
            session.sanitize(events)
            assert session.cache_size > 0

        assert session.cache_size == 0


# ── Audit ──


class TestAudit:
    def test_audit_shows_detected_fields(self):
        events = _load_fixture("esinta_sample.json")[:3]
        session = SanitizeSession(profiles=["esinta"], seed="audit-test")
        report = session.audit(events)

        assert "username" in report
        assert report["username"]["type"] == "USERNAME"
        assert "hostname" in report
        assert report["hostname"]["type"] == "HOSTNAME"
