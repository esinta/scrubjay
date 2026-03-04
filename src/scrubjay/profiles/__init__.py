"""Profile loader and discovery.

Loads YAML profile definitions and converts them to Profile objects
with validated ScrubRule lists.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from scrubjay.core.types import FieldType, Profile, ScrubRule, Tier
from scrubjay.profiles._schema import validate_profile_data

_PROFILES_DIR = Path(__file__).parent


def _tier_from_int(value: int) -> Tier:
    """Convert integer tier value to Tier enum."""
    return Tier(value)


def _parse_profile(data: dict) -> Profile:
    """Convert a validated YAML dict into a Profile object."""
    profile_section = data.get("profile", {})
    fields_section = data.get("fields", [])
    internal_domains = data.get("internal_domains", [])

    rules: list[ScrubRule] = []
    for field_def in fields_section:
        mc = field_def.get("match_condition")
        rules.append(
            ScrubRule(
                field_name=field_def["field"],
                field_type=FieldType[field_def["type"]],
                tier=_tier_from_int(field_def["tier"]),
                description=field_def.get("description", ""),
                match_condition=mc,
            )
        )

    return Profile(
        name=profile_section.get("name", ""),
        version=profile_section.get("version", ""),
        description=profile_section.get("description", ""),
        sourcetypes=profile_section.get("sourcetypes", []),
        indexes=profile_section.get("indexes", []),
        author=profile_section.get("author", ""),
        url=profile_section.get("url", ""),
        internal_domains=internal_domains,
        fields=rules,
        raw_config=data,
    )


def load_profile(name: str) -> Profile:
    """Load a built-in YAML profile by name.

    Args:
        name: Profile name, e.g. "okta".

    Returns:
        A validated Profile object.

    Raises:
        FileNotFoundError: If no profile with that name exists.
        ValueError: If the profile fails validation.
    """
    path = _PROFILES_DIR / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"No built-in profile named '{name}'")
    return load_profile_from_file(str(path))


def load_profile_from_file(path: str) -> Profile:
    """Load a profile from an arbitrary file path.

    Args:
        path: Path to a YAML profile file.

    Returns:
        A validated Profile object.

    Raises:
        FileNotFoundError: If the file doesn't exist.
        ValueError: If the profile fails validation.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Profile file not found: {path}")

    with open(file_path) as f:
        data = yaml.safe_load(f)

    errors = validate_profile_data(data)
    if errors:
        raise ValueError(
            f"Profile validation failed for {path}:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    return _parse_profile(data)


def list_profiles() -> list[str]:
    """Return names of all built-in profiles.

    Returns:
        List of profile names (without .yaml extension).
    """
    return sorted(
        p.stem
        for p in _PROFILES_DIR.glob("*.yaml")
        if not p.name.startswith("_")
    )


def validate_profile(path: str) -> list[str]:
    """Validate a profile YAML file and return errors.

    Args:
        path: Path to a YAML profile file.

    Returns:
        List of validation error strings. Empty if valid.
    """
    file_path = Path(path)
    if not file_path.exists():
        return [f"File not found: {path}"]

    try:
        with open(file_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML parse error: {e}"]

    return validate_profile_data(data)
