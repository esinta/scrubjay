"""SanitizeSession orchestrator.

The main public API that wires together the detector, tokenizer, and cache.
Provides sanitize/restore/audit operations and context manager support.

Uses a two-pass sanitization approach:
1. First pass: detect and tokenize all non-FREETEXT fields
2. Second pass: detect FREETEXT fields with known-entity matching
"""

from __future__ import annotations

import copy
import csv
import io
import json
from collections import defaultdict
from typing import Any

from scrubjay.core.cache import TokenCache
from scrubjay.core.detector import Detector
from scrubjay.core.tokenizer import Tokenizer
from scrubjay.core.types import (
    FieldType,
    Profile,
    ScrubResult,
    ScrubRule,
    Tier,
)


class SanitizeSession:
    """Orchestrates detection, tokenization, and caching for data sanitization.

    Usage:
        session = SanitizeSession(profiles=["okta"])
        result = session.sanitize(raw_data)
        restored = session.restore(llm_response)
    """

    def __init__(
        self,
        profiles: list[str | Profile],
        tier: Tier | None = None,
        seed: str | None = None,
        custom_rules: list[ScrubRule] | None = None,
        config_path: str | None = None,
    ) -> None:
        """Initialize a sanitization session.

        Args:
            profiles: Profile names (strings) or Profile objects.
            tier: Maximum tier level to scrub. None = use config default or DEFAULT.
            seed: Optional seed for reproducible tokenization.
            custom_rules: Additional ad-hoc rules to apply.
            config_path: Optional explicit path to user config file.
        """
        from scrubjay.core.config import load_user_config
        from scrubjay.profiles import load_profile

        user_config = load_user_config(config_path)

        loaded_profiles: list[Profile] = []
        for p in profiles:
            if isinstance(p, str):
                loaded_profiles.append(load_profile(p))
            else:
                loaded_profiles.append(p)

        # Apply user config overrides
        if user_config.get("internal_domains"):
            for lp in loaded_profiles:
                lp.internal_domains = user_config["internal_domains"]

        # Merge custom_rules from config and parameter
        all_custom_rules = list(custom_rules or [])
        for cr in user_config.get("custom_rules", []):
            all_custom_rules.append(
                ScrubRule(
                    field_name=cr["field"],
                    field_type=FieldType[cr["type"]],
                    tier=Tier(cr["tier"]),
                    description=cr.get("description", ""),
                )
            )

        if all_custom_rules:
            custom_profile = Profile(
                name="_custom",
                version="1.0",
                description="Ad-hoc custom rules",
                fields=all_custom_rules,
            )
            loaded_profiles.append(custom_profile)

        # Resolve tier: explicit param > config > DEFAULT
        if tier is not None:
            self.tier = tier
        elif "default_tier" in user_config:
            self.tier = Tier(user_config["default_tier"])
        else:
            self.tier = Tier.DEFAULT

        self._detector = Detector(loaded_profiles)
        self._tokenizer = Tokenizer(seed=seed)
        self._cache = TokenCache()

    def sanitize(self, data: dict | list[dict] | str) -> ScrubResult:
        """Sanitize input data using two-pass detection.

        Pass 1: Detect and tokenize all non-FREETEXT fields.
        Pass 2: Detect FREETEXT fields with known-entity matching enabled.

        Args:
            data: Input data to sanitize.

        Returns:
            ScrubResult with sanitized_data and stats.
        """
        records = self._normalize_input(data)
        sanitized = copy.deepcopy(records)

        for i, record in enumerate(records):
            # Pass 1: non-FREETEXT fields (no cache needed for detection)
            detections = self._detector.detect(record, self.tier)
            freetext_detections = []

            for det in detections:
                if det.field_type == FieldType.PASSTHROUGH:
                    continue
                if det.field_type == FieldType.FREETEXT:
                    freetext_detections.append(det)
                    continue
                # Handle sub-entity detections from FREETEXT (username/host)
                if "::" in det.field_path:
                    continue  # Will be handled in pass 2
                token = self._cache.get_or_create(
                    det.raw_value, det.field_type, det.field_path,
                    self._tokenizer,
                )
                self._set_nested_value(sanitized[i], det.field_path, token)

            # Pass 2: FREETEXT fields with known-entity matching
            # Re-detect with cache for entity matching
            detections_pass2 = self._detector.detect(
                record, self.tier, cache=self._cache
            )

            for det in detections_pass2:
                if det.field_type == FieldType.PASSTHROUGH:
                    continue
                if det.field_type == FieldType.FREETEXT:
                    continue
                if "::" not in det.field_path:
                    continue  # Already handled in pass 1
                # Sub-entity from FREETEXT — tokenize it
                token = self._cache.get_or_create(
                    det.raw_value, det.field_type, det.field_path,
                    self._tokenizer,
                )

            # Now replace FREETEXT values with sub-entity replacements
            for det in freetext_detections:
                base_path = det.field_path
                text = det.raw_value
                # Apply all cached replacements to the text
                text = self._cache.restore_text_reverse(text)
                self._set_nested_value(sanitized[i], base_path, text)

        result_data: Any
        if isinstance(data, dict):
            result_data = sanitized[0] if sanitized else {}
        else:
            result_data = sanitized

        return ScrubResult(
            sanitized_data=result_data, stats=self._cache.stats()
        )

    def restore(self, text: str) -> str:
        """Restore all known tokens in text back to real values."""
        return self._cache.restore_text(text)

    def restore_data(self, data: dict | list[dict]) -> dict | list[dict]:
        """Restore tokens in structured data back to real values."""
        result = copy.deepcopy(data)
        if isinstance(result, dict):
            self._restore_dict(result)
        elif isinstance(result, list):
            for item in result:
                if isinstance(item, dict):
                    self._restore_dict(item)
        return result

    def audit(self, data: dict | list[dict] | str) -> dict:
        """Dry-run: show what would be scrubbed without actually doing it."""
        records = self._normalize_input(data)
        field_info: dict[str, dict] = defaultdict(
            lambda: {
                "type": "", "tier": 0,
                "unique_values": set(), "samples": [],
            }
        )

        for record in records:
            detections = self._detector.detect(record, self.tier)
            for det in detections:
                info = field_info[det.field_path]
                info["type"] = det.field_type.name
                info["tier"] = det.tier.value
                info["unique_values"].add(det.raw_value)
                if (
                    len(info["samples"]) < 3
                    and det.raw_value not in info["samples"]
                ):
                    info["samples"].append(det.raw_value)

        result = {}
        for path, info in field_info.items():
            result[path] = {
                "type": info["type"],
                "tier": info["tier"],
                "unique_count": len(info["unique_values"]),
                "sample_values": info["samples"],
            }
        return result

    @property
    def stats(self) -> dict:
        """Scrubbing statistics for this session."""
        return self._cache.stats()

    @property
    def cache_size(self) -> int:
        """Number of unique values currently cached."""
        return len(self._cache)

    def close(self) -> None:
        """Destroy the session cache."""
        self._cache.clear()

    def __enter__(self) -> SanitizeSession:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ── Private helpers ──

    def _normalize_input(self, data: dict | list[dict] | str) -> list[dict]:
        """Convert input data to a list of dicts."""
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    return [parsed]
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                pass
            reader = csv.DictReader(io.StringIO(data))
            rows = list(reader)
            if rows:
                return rows
            return []
        elif isinstance(data, dict):
            return [data]
        elif isinstance(data, list):
            return data
        return []

    def _set_nested_value(self, data: dict, path: str, value: str) -> None:
        """Set a value in a nested dict using dot-notation path."""
        # Strip sub-entity suffixes (e.g., command_line::username)
        if "::" in path:
            return  # Sub-entities are handled via text replacement
        parts = path.split(".")
        current: Any = data
        for part in parts[:-1]:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return
            else:
                return
        last = parts[-1]
        if isinstance(current, dict):
            current[last] = value
        elif isinstance(current, list):
            try:
                current[int(last)] = value
            except (ValueError, IndexError):
                pass

    def _restore_dict(self, data: dict) -> None:
        """Recursively restore all string values in a dict."""
        for key, value in data.items():
            if isinstance(value, str):
                restored = self._cache.restore(value)
                if restored is not None:
                    data[key] = restored
                else:
                    # Try text-level restore for FREETEXT fields
                    new_val = self._cache.restore_text(value)
                    if new_val != value:
                        data[key] = new_val
            elif isinstance(value, dict):
                self._restore_dict(value)
            elif isinstance(value, list):
                self._restore_list(value)

    def _restore_list(self, data: list) -> None:
        """Recursively restore all string values in a list."""
        for i, item in enumerate(data):
            if isinstance(item, str):
                restored = self._cache.restore(item)
                if restored is not None:
                    data[i] = restored
                else:
                    new_val = self._cache.restore_text(item)
                    if new_val != item:
                        data[i] = new_val
            elif isinstance(item, dict):
                self._restore_dict(item)
            elif isinstance(item, list):
                self._restore_list(item)
