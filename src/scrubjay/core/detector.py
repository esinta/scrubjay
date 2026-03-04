"""Sensitive value identification in structured security data.

The detector operates on structured data (dicts, lists of dicts) rather than
raw text. It uses loaded profiles to know which fields are sensitive and what
type they are. Fields are matched via exact paths, array wildcards [*], and
glob wildcards (*).
"""

from __future__ import annotations

import fnmatch
import re

from scrubjay.core.types import Detection, Profile, ScrubRule, Tier


class Detector:
    """Identifies sensitive values in structured security data using profiles.

    Supports exact field paths, array wildcard paths (target[*].displayName),
    glob wildcard paths (debugContext.debugData.*), and conditional rules.
    """

    def __init__(self, profiles: list[Profile]) -> None:
        """Initialize with one or more sourcetype profiles.

        Args:
            profiles: List of Profile objects defining field rules.
        """
        self._exact_fields: dict[str, list[ScrubRule]] = {}
        self._wildcard_fields: list[tuple[str, ScrubRule]] = []
        self._array_fields: list[tuple[str, ScrubRule]] = []
        self._conditional_rules: list[tuple[ScrubRule, dict]] = []

        for profile in profiles:
            for rule in profile.fields:
                if rule.match_condition:
                    self._conditional_rules.append((rule, rule.match_condition))
                elif "[*]" in rule.field_name:
                    self._array_fields.append((rule.field_name, rule))
                elif "*" in rule.field_name:
                    self._wildcard_fields.append((rule.field_name, rule))
                else:
                    self._exact_fields.setdefault(rule.field_name, []).append(rule)

    def _tier_matches(self, rule_tier: Tier, requested_tier: Tier) -> bool:
        """Check if a rule should be applied at the requested tier level.

        At ALWAYS (1): only scrub tier 1 fields.
        At DEFAULT (2): scrub tier 1 and 2 fields.
        NEVER (3) fields are never scrubbed regardless.
        """
        if rule_tier == Tier.NEVER:
            return False
        return rule_tier.value <= requested_tier.value

    def _match_array_pattern(self, field_path: str, pattern: str) -> bool:
        """Check if a field path matches an array wildcard pattern.

        Converts numeric indices in the path to [*] for matching.
        E.g., target.0.displayName matches target[*].displayName.
        """
        # Convert target.0.displayName -> target[*].displayName
        # The dot before the index becomes [*] (replacing ".N." with "[*].")
        normalized = re.sub(r"\.(\d+)(?=\.|$)", "[*]", field_path)
        return normalized == pattern

    def _match_wildcard_pattern(self, field_path: str, pattern: str) -> bool:
        """Check if a field path matches a glob wildcard pattern.

        E.g., debugContext.debugData.requestUri matches debugContext.debugData.*
        """
        return fnmatch.fnmatch(field_path, pattern)

    def _check_conditional_rule(
        self, record: dict, field_path: str, rule: ScrubRule, condition: dict
    ) -> bool:
        """Check if a conditional rule applies based on sibling field values.

        For array elements, checks the sibling field at the same array index.
        """
        cond_field = condition.get("field", "")
        cond_equals = condition.get("equals", "")

        # For array wildcards, resolve the condition field at the same index
        # E.g., if field_path is target.0.displayName and cond_field is target[*].type
        match = re.match(r"^(.+)\.(\d+)\.(.+)$", field_path)
        if match and "[*]" in cond_field:
            array_base = match.group(1)
            index = match.group(2)
            cond_resolved = cond_field.replace(
                f"{array_base}[*]", f"{array_base}.{index}"
            )
            # Resolve using dot notation
            value = self._get_nested_value(record, cond_resolved)
            return value == cond_equals

        return False

    def _get_nested_value(self, data: dict, path: str) -> object:
        """Get a value from nested dict using dot notation."""
        parts = path.split(".")
        current: object = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
        return current

    def detect(self, record: dict, tier: Tier = Tier.DEFAULT) -> list[Detection]:
        """Scan a single record and return all detected sensitive values.

        Args:
            record: A single event as a dict.
            tier: Maximum tier level to scrub. ALWAYS=tier1 only, DEFAULT=tier1+2.

        Returns:
            List of Detection objects for each sensitive value found.
        """
        detections: list[Detection] = []
        self._walk(record, "", tier, record, detections)
        return detections

    def _walk(
        self,
        data: object,
        prefix: str,
        tier: Tier,
        root_record: dict,
        detections: list[Detection],
    ) -> None:
        """Recursively walk a data structure and detect sensitive values."""
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                self._walk(value, path, tier, root_record, detections)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                path = f"{prefix}.{i}"
                self._walk(item, path, tier, root_record, detections)
        else:
            # Leaf value — check for matches
            if data is None or data == "":
                return
            str_value = str(data)
            if not str_value:
                return
            self._check_field(prefix, str_value, tier, root_record, detections)

    def _check_field(
        self,
        field_path: str,
        value: str,
        tier: Tier,
        root_record: dict,
        detections: list[Detection],
    ) -> None:
        """Check a single field path/value against all rules."""
        matched = False

        # Check conditional rules first (they are more specific)
        for rule, condition in self._conditional_rules:
            pattern = rule.field_name
            is_match = False
            if "[*]" in pattern:
                is_match = self._match_array_pattern(field_path, pattern)
            elif "*" in pattern:
                is_match = self._match_wildcard_pattern(field_path, pattern)
            else:
                is_match = field_path == pattern

            if is_match and self._tier_matches(rule.tier, tier):
                if self._check_conditional_rule(
                    root_record, field_path, rule, condition
                ):
                    detections.append(
                        Detection(
                            field_path=field_path,
                            raw_value=value,
                            field_type=rule.field_type,
                            tier=rule.tier,
                        )
                    )
                    matched = True
                    break

        if matched:
            return

        # Check exact fields
        if field_path in self._exact_fields:
            for rule in self._exact_fields[field_path]:
                if self._tier_matches(rule.tier, tier):
                    detections.append(
                        Detection(
                            field_path=field_path,
                            raw_value=value,
                            field_type=rule.field_type,
                            tier=rule.tier,
                        )
                    )
                    return

        # Check array wildcard fields
        for pattern, rule in self._array_fields:
            if self._match_array_pattern(field_path, pattern):
                if self._tier_matches(rule.tier, tier):
                    detections.append(
                        Detection(
                            field_path=field_path,
                            raw_value=value,
                            field_type=rule.field_type,
                            tier=rule.tier,
                        )
                    )
                    return

        # Check glob wildcard fields
        for pattern, rule in self._wildcard_fields:
            if self._match_wildcard_pattern(field_path, pattern):
                if self._tier_matches(rule.tier, tier):
                    detections.append(
                        Detection(
                            field_path=field_path,
                            raw_value=value,
                            field_type=rule.field_type,
                            tier=rule.tier,
                        )
                    )
                    return

    def detect_batch(
        self, records: list[dict], tier: Tier = Tier.DEFAULT
    ) -> list[list[Detection]]:
        """Scan multiple records. Returns parallel list of detection lists.

        Args:
            records: List of event dicts.
            tier: Maximum tier level to scrub.

        Returns:
            List of detection lists, one per input record.
        """
        return [self.detect(record, tier) for record in records]
