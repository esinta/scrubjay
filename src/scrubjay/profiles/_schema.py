"""Profile YAML validation.

Validates profile YAML files against the expected schema, checking required
fields, valid FieldType names, valid tier values, and match_condition structure.
"""

from __future__ import annotations

from scrubjay.core.types import FieldType

VALID_FIELD_TYPES = {ft.name for ft in FieldType}
VALID_TIERS = {1, 2, 3}


def validate_profile_data(data: dict) -> list[str]:
    """Validate a parsed profile YAML dict.

    Args:
        data: The parsed YAML data.

    Returns:
        List of validation error messages. Empty if valid.
    """
    errors: list[str] = []

    # Check top-level structure
    if not isinstance(data, dict):
        return ["Profile data must be a YAML mapping"]

    # Check profile section
    profile = data.get("profile")
    if not isinstance(profile, dict):
        errors.append("Missing required 'profile' section")
    else:
        for req in ("name", "version"):
            if req not in profile:
                errors.append(f"Missing required field 'profile.{req}'")

    # Check fields section
    fields = data.get("fields")
    if fields is None:
        errors.append("Missing required 'fields' section")
    elif not isinstance(fields, list):
        errors.append("'fields' must be a list")
    else:
        for i, field_def in enumerate(fields):
            if not isinstance(field_def, dict):
                errors.append(f"fields[{i}]: must be a mapping")
                continue

            if "field" not in field_def:
                errors.append(f"fields[{i}]: missing required 'field'")

            ftype = field_def.get("type")
            if ftype is None:
                errors.append(f"fields[{i}]: missing required 'type'")
            elif ftype not in VALID_FIELD_TYPES:
                errors.append(
                    f"fields[{i}]: invalid type '{ftype}'. "
                    f"Must be one of: {', '.join(sorted(VALID_FIELD_TYPES))}"
                )

            tier = field_def.get("tier")
            if tier is None:
                errors.append(f"fields[{i}]: missing required 'tier'")
            elif tier not in VALID_TIERS:
                errors.append(
                    f"fields[{i}]: invalid tier {tier!r}. Must be 1, 2, or 3"
                )

            # Validate match_condition if present
            mc = field_def.get("match_condition")
            if mc is not None:
                if not isinstance(mc, dict):
                    errors.append(f"fields[{i}]: match_condition must be a mapping")
                else:
                    if "field" not in mc:
                        errors.append(
                            f"fields[{i}]: match_condition missing 'field'"
                        )
                    if "equals" not in mc:
                        errors.append(
                            f"fields[{i}]: match_condition missing 'equals'"
                        )

    return errors
