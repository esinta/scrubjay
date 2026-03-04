"""Shared type definitions for ScrubJay.

Defines the core enums, dataclasses, and type structures used throughout
the library: field types, scrubbing tiers, rules, tokens, and profiles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class Tier(Enum):
    """Scrubbing tiers controlling when fields are sanitized.

    Lower numeric value = more aggressive scrubbing.
    ALWAYS (1) fields are scrubbed in all modes.
    DEFAULT (2) fields are scrubbed by default but can be skipped.
    NEVER (3) fields are explicitly preserved (IPs, hashes, timestamps).
    """

    ALWAYS = 1
    DEFAULT = 2
    NEVER = 3

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Tier):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Tier):
            return NotImplemented
        return self.value <= other.value

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Tier):
            return NotImplemented
        return self.value > other.value

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Tier):
            return NotImplemented
        return self.value >= other.value


class FieldType(Enum):
    """Semantic type of a field, determines the replacement strategy.

    Each type has a corresponding generator in the Tokenizer that produces
    structurally valid replacements preserving the data shape.
    """

    EMAIL = auto()
    USERNAME = auto()
    HOSTNAME = auto()
    GROUP_NAME = auto()
    APP_NAME = auto()
    PERSON_NAME = auto()
    ACCOUNT_ID = auto()
    EMAIL_SUBJECT = auto()
    FILENAME = auto()
    DN = auto()
    URL_INTERNAL = auto()
    FREETEXT = auto()
    DOMAIN_INTERNAL = auto()
    MAC_ADDRESS = auto()
    CERTIFICATE_CN = auto()
    FILE_PATH = auto()
    UNC_PATH = auto()
    PASSTHROUGH = auto()


@dataclass
class ScrubRule:
    """A rule defining how a specific field should be handled.

    Attributes:
        field_name: Field path using dot notation, array wildcards [*], or globs (*).
        field_type: Semantic type determining the replacement strategy.
        tier: When to apply this rule (ALWAYS, DEFAULT, or NEVER).
        description: Human-readable explanation for governance review.
        match_condition: Optional condition for conditional rules on array elements.
    """

    field_name: str
    field_type: FieldType
    tier: Tier
    description: str = ""
    match_condition: dict | None = None


@dataclass
class TokenEntry:
    """A single mapping between a real value and its sanitized replacement.

    Attributes:
        real_value: The original sensitive value.
        token_value: The synthetic replacement token.
        field_type: The semantic type used for generation.
        first_seen_field: Which field path this value was first detected in.
    """

    real_value: str
    token_value: str
    field_type: FieldType
    first_seen_field: str


@dataclass
class ScrubResult:
    """Result of a sanitize operation.

    Attributes:
        sanitized_data: The scrubbed data (same structure as input).
        stats: Counts by field type, e.g. {"EMAIL": 14, "USERNAME": 8}.
    """

    sanitized_data: Any
    stats: dict


@dataclass
class Detection:
    """A detected sensitive value in a record.

    Attributes:
        field_path: Dot-notation path to the field, e.g. "actor.displayName".
        raw_value: The actual sensitive value found.
        field_type: Semantic type of the detected value.
        tier: The tier level of the rule that matched.
    """

    field_path: str
    raw_value: str
    field_type: FieldType
    tier: Tier


@dataclass
class Profile:
    """A loaded and validated scrubbing profile.

    Attributes:
        name: Profile identifier, e.g. "okta".
        version: Profile version string.
        description: Human-readable description.
        sourcetypes: Splunk sourcetypes this profile applies to.
        indexes: Splunk indexes this profile applies to.
        author: Profile author.
        url: Reference URL for the data source.
        internal_domains: Domain patterns for FREETEXT detection.
        fields: List of scrub rules defined in this profile.
        raw_config: The full parsed YAML dict for advanced features.
    """

    name: str
    version: str
    description: str
    sourcetypes: list[str] = field(default_factory=list)
    indexes: list[str] = field(default_factory=list)
    author: str = ""
    url: str = ""
    internal_domains: list[str] = field(default_factory=list)
    fields: list[ScrubRule] = field(default_factory=list)
    raw_config: dict = field(default_factory=dict)
