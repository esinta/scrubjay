"""User configuration file loader.

Resolves config from:
1. $SCRUBJAY_CONFIG environment variable
2. ~/.config/scrubjay/config.yaml
3. No config (empty defaults)
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml


def _find_config_path(explicit_path: str | None = None) -> Path | None:
    """Find the user config file path.

    Args:
        explicit_path: Explicitly provided path (highest priority).

    Returns:
        Path to config file, or None if not found.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"Config file not found: {explicit_path}")

    env_path = os.environ.get("SCRUBJAY_CONFIG")
    if env_path:
        p = Path(env_path)
        if p.exists():
            return p

    default_path = Path.home() / ".config" / "scrubjay" / "config.yaml"
    if default_path.exists():
        return default_path

    return None


def load_user_config(explicit_path: str | None = None) -> dict:
    """Load and return the user config as a dict.

    Args:
        explicit_path: Optional explicit path to config file.

    Returns:
        Parsed config dict. Empty dict if no config file found.

    Raises:
        FileNotFoundError: If explicit_path is given but doesn't exist.
        ValueError: If the config file is invalid YAML.
    """
    config_path = _find_config_path(explicit_path)
    if config_path is None:
        return {}

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid config file {config_path}: {e}") from e

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(
            f"Config file {config_path} must be a YAML mapping"
        )

    return data
