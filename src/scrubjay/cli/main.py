"""CLI entry point for ScrubJay.

Provides scrub, restore, audit, and profiles commands.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time

import click

from scrubjay.core.session import SanitizeSession
from scrubjay.core.types import Tier
from scrubjay.profiles import list_profiles, load_profile, validate_profile


def _get_session_dir() -> str:
    """Get or create the session storage directory."""
    d = os.path.join(tempfile.gettempdir(), "scrubjay_sessions")
    os.makedirs(d, exist_ok=True)
    return d


def _save_session_cache(session: SanitizeSession, session_id: str) -> str:
    """Save session cache to a temp file for later restore."""
    session_dir = _get_session_dir()
    path = os.path.join(session_dir, f"{session_id}.json")
    export = session._cache.export()
    with open(path, "w") as f:
        json.dump(export, f)
    # Also save a 'latest' symlink/file
    latest = os.path.join(session_dir, "latest")
    with open(latest, "w") as f:
        f.write(session_id)
    return path


def _load_session_cache(session_id: str) -> dict:
    """Load a saved session cache."""
    session_dir = _get_session_dir()
    if session_id == "latest":
        latest_file = os.path.join(session_dir, "latest")
        if not os.path.exists(latest_file):
            raise click.ClickException("No saved sessions found")
        with open(latest_file) as f:
            session_id = f.read().strip()

    path = os.path.join(session_dir, f"{session_id}.json")
    if not os.path.exists(path):
        raise click.ClickException(f"Session '{session_id}' not found")
    with open(path) as f:
        return json.load(f)


def _read_input(file_path: str | None) -> str:
    """Read input from file or stdin."""
    if file_path:
        with open(file_path) as f:
            return f.read()
    return sys.stdin.read()


def _write_output(content: str, output_path: str | None) -> None:
    """Write output to file or stdout."""
    if output_path:
        with open(output_path, "w") as f:
            f.write(content)
    else:
        click.echo(content)


@click.group()
def cli() -> None:
    """ScrubJay: Sanitize sensitive data in security logs."""


@cli.command()
@click.option("-p", "--profile", "profile_names", required=True,
              help="Profile name(s), comma-separated")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]),
              default=None, help="Input format")
@click.option("--tier", type=click.IntRange(1, 2), default=2,
              help="Max tier to scrub (1=ALWAYS only, 2=DEFAULT)")
@click.option("-f", "--file", "file_path", default=None,
              help="Input file path")
@click.option("-o", "--output", "output_path", default=None,
              help="Output file path")
def scrub(
    profile_names: str,
    fmt: str | None,
    tier: int,
    file_path: str | None,
    output_path: str | None,
) -> None:
    """Sanitize sensitive data in security logs."""
    profiles = [p.strip() for p in profile_names.split(",")]
    tier_enum = Tier.ALWAYS if tier == 1 else Tier.DEFAULT

    raw = _read_input(file_path)
    session = SanitizeSession(profiles=profiles, tier=tier_enum)

    # Parse input
    if fmt == "csv" or (fmt is None and not raw.lstrip().startswith(("{", "["))):
        # Treat as CSV if explicitly CSV or doesn't look like JSON
        if raw.lstrip().startswith(("{", "[")):
            data = json.loads(raw)
        else:
            data = raw
    else:
        data = json.loads(raw)

    result = session.sanitize(data)
    output = json.dumps(result.sanitized_data, indent=2)
    _write_output(output, output_path)

    # Save session for restore
    session_id = str(int(time.time()))
    cache_path = _save_session_cache(session, session_id)
    click.echo(f"Session saved: {session_id} ({cache_path})", err=True)
    click.echo(f"Stats: {json.dumps(result.stats)}", err=True)


@cli.command()
@click.option("--session", "session_id", required=True, help="Session ID or 'latest'")
@click.option("-f", "--file", "file_path", default=None, help="Input file path")
@click.option("-o", "--output", "output_path", default=None, help="Output file path")
def restore(session_id: str, file_path: str | None, output_path: str | None) -> None:
    """Restore tokenized values back to originals."""
    cache_data = _load_session_cache(session_id)
    text = _read_input(file_path)

    # Build reverse mapping: token -> real_value, sorted by token length desc
    token_map = {}
    for real_value, info in cache_data.items():
        token_map[info["token"]] = real_value

    sorted_tokens = sorted(token_map.keys(), key=len, reverse=True)
    for token in sorted_tokens:
        text = text.replace(token, token_map[token])

    _write_output(text, output_path)


@cli.command()
@click.option("-p", "--profile", "profile_names", required=True,
              help="Profile name(s), comma-separated")
@click.option("-f", "--file", "file_path", default=None,
              help="Input file path")
def audit(profile_names: str, file_path: str | None) -> None:
    """Show what would be scrubbed without actually doing it."""
    profiles = [p.strip() for p in profile_names.split(",")]
    raw = _read_input(file_path)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = raw

    session = SanitizeSession(profiles=profiles)
    report = session.audit(data)

    if not report:
        click.echo("No sensitive fields detected.")
        return

    # Pretty-print the table
    click.echo(f"{'Field':<40} {'Type':<18} {'Tier':<6} {'Unique':<8} {'Sample'}")
    click.echo("-" * 100)
    for field_path, info in sorted(report.items()):
        samples = ", ".join(f'"{s}"' for s in info["sample_values"][:2])
        if info["type"] == "PASSTHROUGH":
            samples = "(not scrubbed)"
        click.echo(
            f"{field_path:<40} {info['type']:<18} {info['tier']:<6} "
            f"{info['unique_count']:<8} {samples}"
        )


@cli.group()
def profiles() -> None:
    """Manage scrubbing profiles."""


@profiles.command("list")
def profiles_list() -> None:
    """List available profiles."""
    for name in list_profiles():
        click.echo(name)


@profiles.command("show")
@click.argument("name")
def profiles_show(name: str) -> None:
    """Display profile field definitions."""
    try:
        profile = load_profile(name)
    except FileNotFoundError:
        raise click.ClickException(f"Profile '{name}' not found")

    click.echo(f"Profile: {profile.name} v{profile.version}")
    click.echo(f"Description: {profile.description}")
    click.echo(f"Author: {profile.author}")
    click.echo()
    click.echo(f"{'Field':<40} {'Type':<18} {'Tier':<6} {'Description'}")
    click.echo("-" * 100)
    for rule in profile.fields:
        click.echo(
            f"{rule.field_name:<40} {rule.field_type.name:<18} {rule.tier.value:<6} "
            f"{rule.description}"
        )


@profiles.command("validate")
@click.argument("path")
def profiles_validate(path: str) -> None:
    """Validate a custom profile YAML file."""
    errors = validate_profile(path)
    if errors:
        for err in errors:
            click.echo(f"ERROR: {err}", err=True)
        raise SystemExit(1)
    click.echo("Valid.")
