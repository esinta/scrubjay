"""Tests for the CLI."""

import json
import os

from click.testing import CliRunner

from scrubjay.cli.main import cli

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
OKTA_FIXTURE = os.path.join(FIXTURE_DIR, "okta_sample.json")


class TestProfilesCommands:
    def test_profiles_list(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["profiles", "list"])
        assert result.exit_code == 0
        assert "okta" in result.output

    def test_profiles_show(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["profiles", "show", "okta"])
        assert result.exit_code == 0
        assert "actor.displayName" in result.output
        assert "PERSON_NAME" in result.output

    def test_profiles_show_not_found(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["profiles", "show", "nonexistent"])
        assert result.exit_code != 0

    def test_profiles_validate_okta(self):
        runner = CliRunner()
        okta_path = os.path.join(
            os.path.dirname(__file__),
            "..", "src", "scrubjay", "profiles", "okta.yaml"
        )
        result = runner.invoke(cli, ["profiles", "validate", okta_path])
        assert result.exit_code == 0
        assert "Valid" in result.output


class TestScrubCommand:
    def test_scrub_from_file(self):
        if not os.path.exists(OKTA_FIXTURE):
            return
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["scrub", "-p", "okta", "-f", OKTA_FIXTURE, "-o", "scrubbed.json"],
            )
            assert result.exit_code == 0
            with open("scrubbed.json") as f:
                data = json.loads(f.read())
            assert isinstance(data, list)
            assert len(data) > 0

    def test_scrub_with_output_file(self):
        if not os.path.exists(OKTA_FIXTURE):
            return
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(
                cli,
                ["scrub", "-p", "okta", "-f", OKTA_FIXTURE, "-o", "out.json"],
            )
            assert result.exit_code == 0
            assert os.path.exists("out.json")
            with open("out.json") as f:
                data = json.loads(f.read())
            assert isinstance(data, list)

    def test_scrub_from_stdin(self):
        runner = CliRunner()
        data = json.dumps({"actor": {"displayName": "John Smith", "alternateId": "john@test.com"}})
        result = runner.invoke(cli, ["scrub", "-p", "okta"], input=data)
        assert result.exit_code == 0

    def test_scrub_tier1_only(self):
        if not os.path.exists(OKTA_FIXTURE):
            return
        runner = CliRunner()
        result = runner.invoke(cli, ["scrub", "-p", "okta", "--tier", "1", "-f", OKTA_FIXTURE])
        assert result.exit_code == 0


class TestAuditCommand:
    def test_audit(self):
        if not os.path.exists(OKTA_FIXTURE):
            return
        runner = CliRunner()
        result = runner.invoke(cli, ["audit", "-p", "okta", "-f", OKTA_FIXTURE])
        assert result.exit_code == 0
        assert "PERSON_NAME" in result.output or "Field" in result.output


class TestRestoreCommand:
    def test_scrub_then_restore(self):
        if not os.path.exists(OKTA_FIXTURE):
            return
        runner = CliRunner()
        # First scrub
        result = runner.invoke(cli, ["scrub", "-p", "okta", "-f", OKTA_FIXTURE])
        assert result.exit_code == 0
        sanitized_output = result.output

        # Now restore using latest session
        result = runner.invoke(
            cli, ["restore", "--session", "latest"], input=sanitized_output
        )
        assert result.exit_code == 0
