"""Tests for the Detector."""

from scrubjay.core.detector import Detector
from scrubjay.core.types import FieldType, Profile, ScrubRule, Tier


def _make_profile(rules: list[ScrubRule]) -> Profile:
    return Profile(name="test", version="1.0", description="test", fields=rules)


class TestExactFieldMatching:
    def test_simple_field(self):
        profile = _make_profile([
            ScrubRule("actor.displayName", FieldType.PERSON_NAME, Tier.ALWAYS),
        ])
        detector = Detector([profile])
        record = {"actor": {"displayName": "John Smith"}}
        detections = detector.detect(record)
        assert len(detections) == 1
        assert detections[0].field_path == "actor.displayName"
        assert detections[0].raw_value == "John Smith"
        assert detections[0].field_type == FieldType.PERSON_NAME

    def test_nested_field(self):
        profile = _make_profile([
            ScrubRule("a.b.c", FieldType.USERNAME, Tier.ALWAYS),
        ])
        detector = Detector([profile])
        record = {"a": {"b": {"c": "jsmith"}}}
        detections = detector.detect(record)
        assert len(detections) == 1
        assert detections[0].raw_value == "jsmith"


class TestArrayWildcard:
    def test_array_wildcard(self):
        profile = _make_profile([
            ScrubRule("target[*].displayName", FieldType.PERSON_NAME, Tier.ALWAYS),
        ])
        detector = Detector([profile])
        record = {
            "target": [
                {"displayName": "Alice", "type": "User"},
                {"displayName": "Bob", "type": "User"},
            ]
        }
        detections = detector.detect(record)
        assert len(detections) == 2
        values = {d.raw_value for d in detections}
        assert values == {"Alice", "Bob"}


class TestGlobWildcard:
    def test_glob_wildcard(self):
        profile = _make_profile([
            ScrubRule("debugContext.debugData.*", FieldType.FREETEXT, Tier.DEFAULT),
        ])
        detector = Detector([profile])
        record = {
            "debugContext": {
                "debugData": {
                    "requestUri": "/api/v1/users",
                    "url": "https://example.com",
                }
            }
        }
        detections = detector.detect(record, tier=Tier.DEFAULT)
        assert len(detections) == 2


class TestTierFiltering:
    def test_always_only_gets_tier1(self):
        profile = _make_profile([
            ScrubRule("f1", FieldType.USERNAME, Tier.ALWAYS),
            ScrubRule("f2", FieldType.APP_NAME, Tier.DEFAULT),
            ScrubRule("f3", FieldType.PASSTHROUGH, Tier.NEVER),
        ])
        detector = Detector([profile])
        record = {"f1": "user1", "f2": "AppX", "f3": "10.0.0.1"}
        detections = detector.detect(record, tier=Tier.ALWAYS)
        assert len(detections) == 1
        assert detections[0].field_path == "f1"

    def test_default_gets_tier1_and_tier2(self):
        profile = _make_profile([
            ScrubRule("f1", FieldType.USERNAME, Tier.ALWAYS),
            ScrubRule("f2", FieldType.APP_NAME, Tier.DEFAULT),
            ScrubRule("f3", FieldType.PASSTHROUGH, Tier.NEVER),
        ])
        detector = Detector([profile])
        record = {"f1": "user1", "f2": "AppX", "f3": "10.0.0.1"}
        detections = detector.detect(record, tier=Tier.DEFAULT)
        assert len(detections) == 2
        paths = {d.field_path for d in detections}
        assert paths == {"f1", "f2"}

    def test_never_fields_always_skipped(self):
        profile = _make_profile([
            ScrubRule("f1", FieldType.PASSTHROUGH, Tier.NEVER),
        ])
        detector = Detector([profile])
        record = {"f1": "anything"}
        detections = detector.detect(record, tier=Tier.DEFAULT)
        assert len(detections) == 0


class TestConditionalRules:
    def test_conditional_match(self):
        profile = _make_profile([
            ScrubRule(
                "target[*].displayName",
                FieldType.APP_NAME,
                Tier.DEFAULT,
                match_condition={"field": "target[*].type", "equals": "AppInstance"},
            ),
        ])
        detector = Detector([profile])
        record = {
            "target": [
                {"displayName": "Workday", "type": "AppInstance"},
                {"displayName": "John Smith", "type": "User"},
            ]
        }
        detections = detector.detect(record, tier=Tier.DEFAULT)
        assert len(detections) == 1
        assert detections[0].raw_value == "Workday"
        assert detections[0].field_type == FieldType.APP_NAME

    def test_conditional_no_match(self):
        profile = _make_profile([
            ScrubRule(
                "target[*].displayName",
                FieldType.APP_NAME,
                Tier.DEFAULT,
                match_condition={"field": "target[*].type", "equals": "AppInstance"},
            ),
        ])
        detector = Detector([profile])
        record = {
            "target": [
                {"displayName": "John Smith", "type": "User"},
            ]
        }
        detections = detector.detect(record, tier=Tier.DEFAULT)
        assert len(detections) == 0


class TestEdgeCases:
    def test_empty_values_skipped(self):
        profile = _make_profile([
            ScrubRule("f1", FieldType.USERNAME, Tier.ALWAYS),
        ])
        detector = Detector([profile])
        record = {"f1": ""}
        detections = detector.detect(record)
        assert len(detections) == 0

    def test_null_values_skipped(self):
        profile = _make_profile([
            ScrubRule("f1", FieldType.USERNAME, Tier.ALWAYS),
        ])
        detector = Detector([profile])
        record = {"f1": None}
        detections = detector.detect(record)
        assert len(detections) == 0

    def test_unknown_fields_ignored(self):
        profile = _make_profile([
            ScrubRule("known_field", FieldType.USERNAME, Tier.ALWAYS),
        ])
        detector = Detector([profile])
        record = {"unknown_field": "value", "known_field": "jsmith"}
        detections = detector.detect(record)
        assert len(detections) == 1
        assert detections[0].field_path == "known_field"

    def test_detect_batch(self):
        profile = _make_profile([
            ScrubRule("name", FieldType.PERSON_NAME, Tier.ALWAYS),
        ])
        detector = Detector([profile])
        records = [{"name": "Alice"}, {"name": "Bob"}, {"other": "x"}]
        results = detector.detect_batch(records)
        assert len(results) == 3
        assert len(results[0]) == 1
        assert len(results[1]) == 1
        assert len(results[2]) == 0
