"""Tests for the SanitizeSession orchestrator."""

import json

from scrubjay.core.session import SanitizeSession
from scrubjay.core.types import FieldType, Profile, ScrubRule, Tier


def _make_profile() -> Profile:
    """Create a simple test profile."""
    return Profile(
        name="test",
        version="1.0",
        description="Test profile",
        fields=[
            ScrubRule("actor.displayName", FieldType.PERSON_NAME, Tier.ALWAYS),
            ScrubRule("actor.alternateId", FieldType.EMAIL, Tier.ALWAYS),
            ScrubRule("actor.id", FieldType.ACCOUNT_ID, Tier.ALWAYS),
            ScrubRule("target[*].displayName", FieldType.PERSON_NAME, Tier.ALWAYS),
            ScrubRule("target[*].alternateId", FieldType.EMAIL, Tier.ALWAYS),
            ScrubRule("app_name", FieldType.APP_NAME, Tier.DEFAULT),
            ScrubRule("eventType", FieldType.PASSTHROUGH, Tier.NEVER),
            ScrubRule("outcome.result", FieldType.PASSTHROUGH, Tier.NEVER),
        ],
    )


def _sample_record() -> dict:
    return {
        "actor": {
            "displayName": "John Smith",
            "alternateId": "jsmith@company.com",
            "id": "00u1abc2def3ghi4jkl",
        },
        "target": [
            {
                "displayName": "Jane Doe",
                "alternateId": "jdoe@company.com",
            }
        ],
        "app_name": "Workday",
        "eventType": "user.session.start",
        "outcome": {"result": "SUCCESS"},
    }


class TestSanitize:
    def test_single_dict(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        result = session.sanitize(_sample_record())
        data = result.sanitized_data
        # Sensitive fields should be tokenized
        assert data["actor"]["displayName"].startswith("PERSON-")
        assert "USER-" in data["actor"]["alternateId"]
        assert data["actor"]["id"].startswith("ACCT-")
        # Non-sensitive fields should be unchanged
        assert data["eventType"] == "user.session.start"
        assert data["outcome"]["result"] == "SUCCESS"

    def test_list_of_dicts(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        records = [_sample_record(), _sample_record()]
        records[1]["actor"]["displayName"] = "Bob Wilson"
        result = session.sanitize(records)
        assert isinstance(result.sanitized_data, list)
        assert len(result.sanitized_data) == 2

    def test_json_string_input(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        json_str = json.dumps(_sample_record())
        result = session.sanitize(json_str)
        assert isinstance(result.sanitized_data, list)
        assert len(result.sanitized_data) == 1

    def test_tier_filtering(self):
        profile = _make_profile()
        # Tier ALWAYS only — should not scrub APP_NAME (tier 2)
        session = SanitizeSession(profiles=[profile], tier=Tier.ALWAYS, seed="test")
        result = session.sanitize(_sample_record())
        data = result.sanitized_data
        assert data["app_name"] == "Workday"  # Not scrubbed (tier 2)
        assert data["actor"]["displayName"].startswith("PERSON-")  # Scrubbed (tier 1)

    def test_tier_default_scrubs_tier2(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], tier=Tier.DEFAULT, seed="test")
        result = session.sanitize(_sample_record())
        data = result.sanitized_data
        assert data["app_name"].startswith("APP-")  # Scrubbed (tier 2)

    def test_stats_after_sanitize(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        session.sanitize(_sample_record())
        stats = session.stats
        assert stats.get("PERSON_NAME", 0) >= 1
        assert stats.get("EMAIL", 0) >= 1


class TestRestore:
    def test_restore_text(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        result = session.sanitize(_sample_record())
        # Get the token that replaced John Smith
        token = result.sanitized_data["actor"]["displayName"]
        text = f"The user {token} logged in successfully."
        restored = session.restore(text)
        assert "John Smith" in restored
        assert token not in restored

    def test_restore_data(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        result = session.sanitize(_sample_record())
        restored = session.restore_data(result.sanitized_data)
        assert restored["actor"]["displayName"] == "John Smith"
        assert restored["actor"]["alternateId"] == "jsmith@company.com"


class TestRoundTrip:
    def test_full_round_trip(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        original = _sample_record()
        result = session.sanitize(original)
        sanitized = result.sanitized_data

        # Verify sensitive fields are tokenized
        assert sanitized["actor"]["displayName"] != original["actor"]["displayName"]
        assert sanitized["actor"]["alternateId"] != original["actor"]["alternateId"]

        # Verify non-sensitive fields unchanged
        assert sanitized["eventType"] == original["eventType"]
        assert sanitized["outcome"]["result"] == original["outcome"]["result"]

        # Restore and verify matches original
        restored = session.restore_data(sanitized)
        assert restored["actor"]["displayName"] == original["actor"]["displayName"]
        assert restored["actor"]["alternateId"] == original["actor"]["alternateId"]
        assert restored["actor"]["id"] == original["actor"]["id"]

    def test_entity_consistency_across_sanitize_calls(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        record1 = _sample_record()
        record2 = _sample_record()
        r1 = session.sanitize(record1)
        r2 = session.sanitize(record2)
        # Same values should get same tokens
        assert (
            r1.sanitized_data["actor"]["displayName"]
            == r2.sanitized_data["actor"]["displayName"]
        )


class TestAudit:
    def test_audit_returns_field_summary(self):
        profile = _make_profile()
        session = SanitizeSession(profiles=[profile], seed="test")
        report = session.audit(_sample_record())
        assert "actor.displayName" in report
        assert report["actor.displayName"]["type"] == "PERSON_NAME"
        assert report["actor.displayName"]["tier"] == 1
        assert report["actor.displayName"]["unique_count"] == 1


class TestContextManager:
    def test_context_manager_clears_cache(self):
        profile = _make_profile()
        with SanitizeSession(profiles=[profile], seed="test") as session:
            session.sanitize(_sample_record())
            assert session.cache_size > 0
        assert session.cache_size == 0


class TestWithOktaProfile:
    """Integration tests using the real Okta profile and fixture data."""

    def test_round_trip_with_okta_profile(self):
        """Load okta profile, sanitize fixture data, verify round-trip."""
        import os
        fixture_path = os.path.join(
            os.path.dirname(__file__), "fixtures", "okta_sample.json"
        )
        if not os.path.exists(fixture_path):
            return  # Skip if fixtures not yet created

        with open(fixture_path) as f:
            raw_data = json.load(f)

        session = SanitizeSession(profiles=["okta"], seed="test")
        result = session.sanitize(raw_data)
        sanitized = result.sanitized_data

        # Verify sensitive fields are tokenized
        for event in sanitized:
            if "actor" in event:
                display_name = event["actor"].get("displayName", "")
                if display_name:
                    assert display_name.startswith("PERSON-") or display_name == ""
                alt_id = event["actor"].get("alternateId", "")
                if alt_id:
                    assert "USER-" in alt_id

            # Non-sensitive fields should be unchanged
            if "eventType" in event:
                assert not event["eventType"].startswith("PERSON-")
            if "outcome" in event and "result" in event["outcome"]:
                assert event["outcome"]["result"] in {
                    "SUCCESS", "FAILURE", "SKIPPED", "ALLOW", "CHALLENGE",
                }

        # Restore and verify
        restored = session.restore_data(sanitized)
        for i, event in enumerate(restored):
            if "actor" in event and "actor" in raw_data[i]:
                assert (
                    event["actor"].get("displayName")
                    == raw_data[i]["actor"].get("displayName")
                )
                assert (
                    event["actor"].get("alternateId")
                    == raw_data[i]["actor"].get("alternateId")
                )
