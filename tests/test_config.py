"""Tests for user config file support."""

import tempfile

import yaml

from scrubjay.core.config import load_user_config
from scrubjay.core.session import SanitizeSession
from scrubjay.core.types import FieldType, Profile, ScrubRule, Tier


def _write_config(data: dict) -> str:
    """Write config to a temp file, return path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    )
    yaml.dump(data, f)
    f.flush()
    f.close()
    return f.name


class TestLoadConfig:
    def test_explicit_path(self):
        path = _write_config({"default_tier": 1})
        config = load_user_config(path)
        assert config["default_tier"] == 1

    def test_missing_explicit_path_raises(self):
        try:
            load_user_config("/nonexistent/config.yaml")
            assert False, "Should raise"
        except FileNotFoundError:
            pass

    def test_no_config_returns_empty(self):
        config = load_user_config()
        assert isinstance(config, dict)

    def test_invalid_yaml_raises(self):
        f = tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        )
        f.write(": invalid: yaml: {{[")
        f.flush()
        f.close()
        try:
            load_user_config(f.name)
            assert False, "Should raise"
        except ValueError:
            pass


class TestConfigMerge:
    def test_custom_rules_from_config(self):
        config = _write_config({
            "custom_rules": [
                {
                    "field": "custom_field",
                    "type": "USERNAME",
                    "tier": 1,
                    "description": "Custom field",
                }
            ]
        })
        profile = Profile(
            name="test", version="1.0", description="test",
            fields=[
                ScrubRule("name", FieldType.PERSON_NAME, Tier.ALWAYS),
            ],
        )
        session = SanitizeSession(
            profiles=[profile], config_path=config, seed="test"
        )
        record = {"name": "John", "custom_field": "jdoe"}
        result = session.sanitize(record)
        # Both fields should be scrubbed
        assert result.sanitized_data["name"].startswith("PERSON-")
        assert result.sanitized_data["custom_field"].startswith("USER-")

    def test_internal_domains_override(self):
        config = _write_config({
            "internal_domains": ["*.acme.com", "*.acme.internal"]
        })
        profile = Profile(
            name="test", version="1.0", description="test",
            internal_domains=["*.corp.internal"],
            fields=[],
        )
        session = SanitizeSession(
            profiles=[profile], config_path=config, seed="test"
        )
        # Verify the override happened (check internal state)
        assert "*.acme.com" in session._detector._internal_domains

    def test_default_tier_from_config(self):
        config = _write_config({"default_tier": 1})
        profile = Profile(
            name="test", version="1.0", description="test",
            fields=[
                ScrubRule("f1", FieldType.USERNAME, Tier.ALWAYS),
                ScrubRule("f2", FieldType.APP_NAME, Tier.DEFAULT),
            ],
        )
        session = SanitizeSession(
            profiles=[profile], config_path=config, seed="test"
        )
        assert session.tier == Tier.ALWAYS
        result = session.sanitize({"f1": "user", "f2": "App"})
        # f2 should NOT be scrubbed because tier=ALWAYS from config
        assert result.sanitized_data["f2"] == "App"

    def test_explicit_tier_overrides_config(self):
        config = _write_config({"default_tier": 1})
        profile = Profile(
            name="test", version="1.0", description="test",
            fields=[
                ScrubRule("f2", FieldType.APP_NAME, Tier.DEFAULT),
            ],
        )
        session = SanitizeSession(
            profiles=[profile], tier=Tier.DEFAULT,
            config_path=config, seed="test",
        )
        assert session.tier == Tier.DEFAULT
