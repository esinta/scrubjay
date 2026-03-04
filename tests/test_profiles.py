"""Tests for profile loading and validation."""

import tempfile
from pathlib import Path

import yaml

from scrubjay.core.types import FieldType, Tier
from scrubjay.profiles import (
    list_profiles,
    load_profile,
    load_profile_from_file,
    validate_profile,
)


class TestLoadProfile:
    def test_load_okta(self):
        profile = load_profile("okta")
        assert profile.name == "okta"
        assert profile.version == "1.0"
        assert len(profile.fields) > 0

    def test_load_nonexistent_raises(self):
        try:
            load_profile("nonexistent")
            assert False, "Should have raised"
        except FileNotFoundError:
            pass

    def test_okta_fields_have_correct_types(self):
        profile = load_profile("okta")
        for rule in profile.fields:
            assert isinstance(rule.field_type, FieldType)
            assert isinstance(rule.tier, Tier)
            assert isinstance(rule.field_name, str)
            assert len(rule.field_name) > 0


class TestValidation:
    def test_okta_passes_validation(self):
        okta_path = Path(__file__).parent.parent / "src/scrubjay/profiles/okta.yaml"
        errors = validate_profile(str(okta_path))
        assert errors == []

    def test_missing_profile_section(self):
        data = {"fields": [{"field": "f", "type": "USERNAME", "tier": 1}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            errors = validate_profile(f.name)
        assert any("profile" in e for e in errors)

    def test_missing_fields_section(self):
        data = {"profile": {"name": "test", "version": "1.0"}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            errors = validate_profile(f.name)
        assert any("fields" in e for e in errors)

    def test_invalid_field_type(self):
        data = {
            "profile": {"name": "test", "version": "1.0"},
            "fields": [{"field": "f", "type": "INVALID_TYPE", "tier": 1}],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            errors = validate_profile(f.name)
        assert any("invalid type" in e.lower() or "INVALID_TYPE" in e for e in errors)

    def test_invalid_tier(self):
        data = {
            "profile": {"name": "test", "version": "1.0"},
            "fields": [{"field": "f", "type": "USERNAME", "tier": 99}],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            errors = validate_profile(f.name)
        assert any("tier" in e.lower() for e in errors)

    def test_file_not_found(self):
        errors = validate_profile("/nonexistent/path.yaml")
        assert len(errors) == 1
        assert "not found" in errors[0].lower()


class TestListProfiles:
    def test_includes_okta(self):
        profiles = list_profiles()
        assert "okta" in profiles


class TestLoadFromFile:
    def test_valid_file(self):
        data = {
            "profile": {"name": "custom", "version": "1.0"},
            "fields": [{"field": "user", "type": "USERNAME", "tier": 1}],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            profile = load_profile_from_file(f.name)
        assert profile.name == "custom"
        assert len(profile.fields) == 1
        assert profile.fields[0].field_type == FieldType.USERNAME

    def test_invalid_file_raises(self):
        data = {"profile": {"name": "bad"}}  # missing version and fields
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            f.flush()
            try:
                load_profile_from_file(f.name)
                assert False, "Should have raised"
            except ValueError:
                pass
