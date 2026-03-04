"""Tests for core type definitions."""

from scrubjay.core.types import (
    Detection,
    FieldType,
    Profile,
    ScrubResult,
    ScrubRule,
    Tier,
    TokenEntry,
)


class TestTier:
    def test_enum_values(self):
        assert Tier.ALWAYS.value == 1
        assert Tier.DEFAULT.value == 2
        assert Tier.NEVER.value == 3

    def test_membership(self):
        assert len(Tier) == 3

    def test_ordering(self):
        assert Tier.ALWAYS < Tier.DEFAULT
        assert Tier.DEFAULT < Tier.NEVER
        assert Tier.ALWAYS < Tier.NEVER
        assert not (Tier.NEVER < Tier.ALWAYS)

    def test_ordering_le_ge(self):
        assert Tier.ALWAYS <= Tier.ALWAYS
        assert Tier.ALWAYS <= Tier.DEFAULT
        assert Tier.NEVER >= Tier.DEFAULT
        assert Tier.NEVER >= Tier.NEVER

    def test_ordering_gt(self):
        assert Tier.NEVER > Tier.DEFAULT
        assert Tier.DEFAULT > Tier.ALWAYS


class TestFieldType:
    def test_has_all_17_types(self):
        expected = {
            "EMAIL", "USERNAME", "HOSTNAME", "GROUP_NAME", "APP_NAME",
            "PERSON_NAME", "ACCOUNT_ID", "EMAIL_SUBJECT", "FILENAME",
            "DN", "URL_INTERNAL", "FREETEXT", "DOMAIN_INTERNAL",
            "MAC_ADDRESS", "CERTIFICATE_CN", "FILE_PATH", "UNC_PATH",
            "PASSTHROUGH",
        }
        actual = {ft.name for ft in FieldType}
        assert actual == expected

    def test_count(self):
        assert len(FieldType) == 18


class TestScrubRule:
    def test_instantiation(self):
        rule = ScrubRule(
            field_name="actor.displayName",
            field_type=FieldType.PERSON_NAME,
            tier=Tier.ALWAYS,
            description="Full name",
        )
        assert rule.field_name == "actor.displayName"
        assert rule.field_type == FieldType.PERSON_NAME
        assert rule.tier == Tier.ALWAYS

    def test_defaults(self):
        rule = ScrubRule("f", FieldType.USERNAME, Tier.DEFAULT)
        assert rule.description == ""
        assert rule.match_condition is None

    def test_equality(self):
        a = ScrubRule("f", FieldType.EMAIL, Tier.ALWAYS)
        b = ScrubRule("f", FieldType.EMAIL, Tier.ALWAYS)
        assert a == b


class TestTokenEntry:
    def test_instantiation(self):
        entry = TokenEntry("jsmith", "USER-0001", FieldType.USERNAME, "actor.id")
        assert entry.real_value == "jsmith"
        assert entry.token_value == "USER-0001"


class TestScrubResult:
    def test_instantiation(self):
        result = ScrubResult(sanitized_data={"a": "b"}, stats={"EMAIL": 3})
        assert result.sanitized_data == {"a": "b"}
        assert result.stats["EMAIL"] == 3


class TestDetection:
    def test_instantiation(self):
        d = Detection("actor.displayName", "John", FieldType.PERSON_NAME, Tier.ALWAYS)
        assert d.field_path == "actor.displayName"
        assert d.raw_value == "John"


class TestProfile:
    def test_instantiation(self):
        p = Profile(name="okta", version="1.0", description="Okta events")
        assert p.name == "okta"
        assert p.sourcetypes == []
        assert p.fields == []
        assert p.raw_config == {}

    def test_with_fields(self):
        rule = ScrubRule("actor.id", FieldType.ACCOUNT_ID, Tier.ALWAYS)
        p = Profile(name="okta", version="1.0", description="test", fields=[rule])
        assert len(p.fields) == 1
