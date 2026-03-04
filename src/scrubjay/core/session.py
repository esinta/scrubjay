"""SanitizeSession orchestrator.

The main public API that wires together the detector, tokenizer, and cache.
Provides sanitize/restore/audit operations and context manager support.
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
        tier: Tier = Tier.DEFAULT,
        seed: str | None = None,
        custom_rules: list[ScrubRule] | None = None,
    ) -> None:
        """Initialize a sanitization session.

        Args:
            profiles: Profile names (strings) or Profile objects.
            tier: Maximum tier level to scrub. Default is DEFAULT (tier 1+2).
            seed: Optional seed for reproducible tokenization.
            custom_rules: Additional ad-hoc rules to apply.
        """
        from scrubjay.profiles import load_profile

        loaded_profiles: list[Profile] = []
        for p in profiles:
            if isinstance(p, str):
                loaded_profiles.append(load_profile(p))
            else:
                loaded_profiles.append(p)

        # Add custom rules as a synthetic profile
        if custom_rules:
            custom_profile = Profile(
                name="_custom",
                version="1.0",
                description="Ad-hoc custom rules",
                fields=list(custom_rules),
            )
            loaded_profiles.append(custom_profile)

        self.tier = tier
        self._detector = Detector(loaded_profiles)
        self._tokenizer = Tokenizer(seed=seed)
        self._cache = TokenCache()

    def sanitize(self, data: dict | list[dict] | str) -> ScrubResult:
        """Sanitize input data by detecting and replacing sensitive values.

        Accepts a single dict, list of dicts, or a JSON/CSV string.

        Args:
            data: Input data to sanitize.

        Returns:
            ScrubResult with sanitized_data and stats.
        """
        records = self._normalize_input(data)
        sanitized = copy.deepcopy(records)

        for i, record in enumerate(records):
            detections = self._detector.detect(record, self.tier)
            for det in detections:
                if det.field_type == FieldType.PASSTHROUGH:
                    continue
                token = self._cache.get_or_create(
                    det.raw_value, det.field_type, det.field_path, self._tokenizer
                )
                self._set_nested_value(sanitized[i], det.field_path, token)

        result_data: Any
        if isinstance(data, dict):
            result_data = sanitized[0] if sanitized else {}
        else:
            result_data = sanitized

        return ScrubResult(sanitized_data=result_data, stats=self._cache.stats())

    def restore(self, text: str) -> str:
        """Restore all known tokens in text back to real values.

        Args:
            text: Text containing tokens (e.g., an LLM response).

        Returns:
            Text with tokens replaced by original values.
        """
        return self._cache.restore_text(text)

    def restore_data(self, data: dict | list[dict]) -> dict | list[dict]:
        """Restore tokens in structured data back to real values.

        Args:
            data: Structured data containing token values.

        Returns:
            Data with tokens restored to original values.
        """
        result = copy.deepcopy(data)
        if isinstance(result, dict):
            self._restore_dict(result)
        elif isinstance(result, list):
            for item in result:
                if isinstance(item, dict):
                    self._restore_dict(item)
        return result

    def audit(self, data: dict | list[dict] | str) -> dict:
        """Dry-run: show what would be scrubbed without actually doing it.

        Args:
            data: Input data to audit.

        Returns:
            Dict mapping field paths to audit info: type, tier, unique values, samples.
        """
        records = self._normalize_input(data)
        field_info: dict[str, dict] = defaultdict(
            lambda: {"type": "", "tier": 0, "unique_values": set(), "samples": []}
        )

        for record in records:
            detections = self._detector.detect(record, self.tier)
            for det in detections:
                info = field_info[det.field_path]
                info["type"] = det.field_type.name
                info["tier"] = det.tier.value
                info["unique_values"].add(det.raw_value)
                if len(info["samples"]) < 3 and det.raw_value not in info["samples"]:
                    info["samples"].append(det.raw_value)

        # Convert sets to counts for serialization
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
            # Try JSON first
            try:
                parsed = json.loads(data)
                if isinstance(parsed, dict):
                    return [parsed]
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                pass
            # Try CSV
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
        # Set the final value
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
            elif isinstance(item, dict):
                self._restore_dict(item)
            elif isinstance(item, list):
                self._restore_list(item)
