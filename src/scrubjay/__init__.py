"""ScrubJay: Sanitize sensitive data in security logs before sending to LLM APIs."""

from scrubjay.core.types import FieldType, ScrubResult, ScrubRule, Tier, TokenEntry


def __getattr__(name: str):
    if name == "SanitizeSession":
        from scrubjay.core.session import SanitizeSession
        return SanitizeSession
    if name == "load_profile":
        from scrubjay.profiles import load_profile
        return load_profile
    if name == "list_profiles":
        from scrubjay.profiles import list_profiles
        return list_profiles
    raise AttributeError(f"module 'scrubjay' has no attribute {name!r}")


__all__ = [
    "SanitizeSession",
    "FieldType",
    "Tier",
    "ScrubRule",
    "ScrubResult",
    "TokenEntry",
    "load_profile",
    "list_profiles",
]
