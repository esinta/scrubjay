"""Sensitive value identification in structured security data.

The detector operates on structured data (dicts, lists of dicts) rather than
raw text. It uses loaded profiles to know which fields are sensitive and what
type they are. Fields are matched via exact paths, array wildcards [*], and
glob wildcards (*).

For fields marked as FREETEXT, the detector extracts sub-entities:
  - Windows path username extraction (C:\\Users\\<name>\\...)
  - UNC path hostname extraction (\\\\SERVER\\share)
  - Known-entity matching against values already in the session cache
"""

from __future__ import annotations

import fnmatch
import re
from typing import TYPE_CHECKING

from scrubjay.core.types import Detection, FieldType, Profile, ScrubRule, Tier

if TYPE_CHECKING:
    from scrubjay.core.cache import TokenCache

# Compiled regexes for FREETEXT sub-detection
_WINDOWS_USER_PATH_RE = re.compile(
    r"[A-Za-z]:\\(?:Users|Documents and Settings)\\([^\\/:*?\"<>|\s]+)\\",
)
_UNC_PATH_RE = re.compile(
    r"\\\\([^\\/:*?\"<>|\s]+)\\",
)


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
        self._internal_domains: list[str] = []

        for profile in profiles:
            self._internal_domains.extend(profile.internal_domains)
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
        """Check if a rule should be applied at the requested tier level."""
        if rule_tier == Tier.NEVER:
            return False
        return rule_tier.value <= requested_tier.value

    def _match_array_pattern(self, field_path: str, pattern: str) -> bool:
        """Check if a field path matches an array wildcard pattern."""
        normalized = re.sub(r"\.(\d+)(?=\.|$)", "[*]", field_path)
        return normalized == pattern

    def _match_wildcard_pattern(self, field_path: str, pattern: str) -> bool:
        """Check if a field path matches a glob wildcard pattern."""
        return fnmatch.fnmatch(field_path, pattern)

    def _check_conditional_rule(
        self, record: dict, field_path: str, rule: ScrubRule, condition: dict
    ) -> bool:
        """Check if a conditional rule applies based on sibling field values."""
        cond_field = condition.get("field", "")
        cond_equals = condition.get("equals", "")

        match = re.match(r"^(.+)\.(\d+)\.(.+)$", field_path)
        if match and "[*]" in cond_field:
            array_base = match.group(1)
            index = match.group(2)
            cond_resolved = cond_field.replace(
                f"{array_base}[*]", f"{array_base}.{index}"
            )
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

    def detect(
        self,
        record: dict,
        tier: Tier = Tier.DEFAULT,
        cache: TokenCache | None = None,
    ) -> list[Detection]:
        """Scan a single record and return all detected sensitive values.

        Args:
            record: A single event as a dict.
            tier: Maximum tier level to scrub.
            cache: Optional cache for known-entity matching in FREETEXT.

        Returns:
            List of Detection objects for each sensitive value found.
        """
        detections: list[Detection] = []
        self._walk(record, "", tier, record, detections, cache)
        return detections

    def _walk(
        self,
        data: object,
        prefix: str,
        tier: Tier,
        root_record: dict,
        detections: list[Detection],
        cache: TokenCache | None = None,
    ) -> None:
        """Recursively walk a data structure and detect sensitive values."""
        if isinstance(data, dict):
            for key, value in data.items():
                path = f"{prefix}.{key}" if prefix else key
                self._walk(value, path, tier, root_record, detections, cache)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                path = f"{prefix}.{i}"
                self._walk(item, path, tier, root_record, detections, cache)
        else:
            if data is None or data == "":
                return
            str_value = str(data)
            if not str_value:
                return
            self._check_field(
                prefix, str_value, tier, root_record, detections, cache
            )

    def _check_field(
        self,
        field_path: str,
        value: str,
        tier: Tier,
        root_record: dict,
        detections: list[Detection],
        cache: TokenCache | None = None,
    ) -> None:
        """Check a single field path/value against all rules."""
        matched = False
        matched_rule: ScrubRule | None = None

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
                    matched_rule = rule
                    break

        if matched:
            if matched_rule and matched_rule.field_type == FieldType.FREETEXT:
                self._detect_freetext(
                    value, field_path, tier, detections, cache
                )
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
                    if rule.field_type == FieldType.FREETEXT:
                        self._detect_freetext(
                            value, field_path, tier, detections, cache
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
                    if rule.field_type == FieldType.FREETEXT:
                        self._detect_freetext(
                            value, field_path, tier, detections, cache
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
                    if rule.field_type == FieldType.FREETEXT:
                        self._detect_freetext(
                            value, field_path, tier, detections, cache
                        )
                    return

    def _detect_freetext(
        self,
        value: str,
        field_path: str,
        tier: Tier,
        detections: list[Detection],
        cache: TokenCache | None = None,
    ) -> None:
        """Extract sub-entities from FREETEXT field values.

        Detects:
        1. Windows usernames from file paths (C:\\Users\\<name>\\)
        2. Hostnames from UNC paths (\\\\SERVER\\)
        3. Known entities from the cache
        """
        seen: set[str] = set()

        # 1. Windows path username extraction
        for m in _WINDOWS_USER_PATH_RE.finditer(value):
            username = m.group(1)
            if username and username not in seen:
                seen.add(username)
                detections.append(
                    Detection(
                        field_path=f"{field_path}::username",
                        raw_value=username,
                        field_type=FieldType.USERNAME,
                        tier=Tier.ALWAYS,
                    )
                )

        # 2. UNC path hostname extraction
        for m in _UNC_PATH_RE.finditer(value):
            hostname = m.group(1)
            if hostname and hostname not in seen:
                seen.add(hostname)
                detections.append(
                    Detection(
                        field_path=f"{field_path}::hostname",
                        raw_value=hostname,
                        field_type=FieldType.HOSTNAME,
                        tier=Tier.ALWAYS,
                    )
                )

        # 3. Known entity matching from cache
        if cache is not None:
            for real_value, entry in list(cache._real_to_token.items()):
                if entry.field_type in (
                    FieldType.PASSTHROUGH,
                    FieldType.FREETEXT,
                ):
                    continue
                if real_value in seen:
                    continue
                if len(real_value) < 3:
                    continue
                if real_value in value:
                    seen.add(real_value)
                    detections.append(
                        Detection(
                            field_path=f"{field_path}::entity",
                            raw_value=real_value,
                            field_type=entry.field_type,
                            tier=Tier.ALWAYS,
                        )
                    )

    def detect_batch(
        self, records: list[dict], tier: Tier = Tier.DEFAULT
    ) -> list[list[Detection]]:
        """Scan multiple records. Returns parallel list of detection lists."""
        return [self.detect(record, tier) for record in records]
