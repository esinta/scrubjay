"""Bidirectional token cache.

Session-scoped, in-memory mapping between real values and tokens.
Thread-safe via a lock for concurrent access in proxy mode.
Supports longest-match-first restoration to avoid partial replacements.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter

from scrubjay.core.tokenizer import Tokenizer
from scrubjay.core.types import FieldType, TokenEntry

logger = logging.getLogger(__name__)


class TokenCache:
    """Bidirectional, session-scoped mapping between real values and tokens.

    Thread-safe via a lock. Supports get_or_create for sanitization and
    restore/restore_text for desanitization.
    """

    def __init__(self) -> None:
        """Initialize empty bidirectional cache."""
        self._lock = threading.Lock()
        self._real_to_token: dict[str, TokenEntry] = {}
        self._token_to_real: dict[str, TokenEntry] = {}
        self._stats: Counter[str] = Counter()

    def get_or_create(
        self,
        real_value: str,
        field_type: FieldType,
        field_name: str,
        tokenizer: Tokenizer,
    ) -> str:
        """Look up or create a token for a real value.

        If the real_value has been seen before, returns its existing token.
        Otherwise, generates a new token via the tokenizer and caches it.

        Args:
            real_value: The original sensitive value.
            field_type: Semantic type for token generation.
            field_name: Field path where this value was found.
            tokenizer: Tokenizer instance for generating new tokens.

        Returns:
            The token string replacing the real value.
        """
        with self._lock:
            if real_value in self._real_to_token:
                return self._real_to_token[real_value].token_value

            token_value = tokenizer.generate(real_value, field_type)

            entry = TokenEntry(
                real_value=real_value,
                token_value=token_value,
                field_type=field_type,
                first_seen_field=field_name,
            )
            self._real_to_token[real_value] = entry
            self._token_to_real[token_value] = entry
            self._stats[field_type.name] += 1
            return token_value

    def restore(self, token_value: str) -> str | None:
        """Look up a token and return the original real value.

        Args:
            token_value: The synthetic token to look up.

        Returns:
            The original real value, or None if not found.
        """
        with self._lock:
            entry = self._token_to_real.get(token_value)
            return entry.real_value if entry else None

    def restore_text(self, text: str) -> str:
        """Replace all known tokens in text with their real values.

        Uses longest-match-first ordering to avoid partial replacement
        (e.g., USER-0041@ORG-001.com is restored before USER-0041 alone).

        Args:
            text: Text containing tokens to restore.

        Returns:
            Text with all known tokens replaced by real values.
        """
        with self._lock:
            # Sort tokens by length descending for longest-match-first
            sorted_tokens = sorted(
                self._token_to_real.keys(), key=len, reverse=True
            )

        for token in sorted_tokens:
            entry = self._token_to_real[token]
            text = text.replace(token, entry.real_value)
        return text

    def stats(self) -> dict[str, int]:
        """Return scrubbing statistics: counts by field type.

        Returns:
            Dict mapping field type names to counts.
        """
        with self._lock:
            return dict(self._stats)

    def export(self) -> dict[str, dict]:
        """Export the full mapping as a dict. For debugging/audit only.

        WARNING: The exported data contains real sensitive values.

        Returns:
            Dict mapping real values to their token info.
        """
        logger.warning(
            "Exporting token cache — output contains real sensitive values."
        )
        with self._lock:
            return {
                real: {
                    "token": entry.token_value,
                    "type": entry.field_type.name,
                    "first_seen_field": entry.first_seen_field,
                }
                for real, entry in self._real_to_token.items()
            }

    def __len__(self) -> int:
        """Number of unique values in the cache."""
        with self._lock:
            return len(self._real_to_token)

    def clear(self) -> None:
        """Destroy all mappings. Called on session end."""
        with self._lock:
            self._real_to_token.clear()
            self._token_to_real.clear()
            self._stats.clear()
