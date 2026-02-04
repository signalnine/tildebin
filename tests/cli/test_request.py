"""Tests for boxctl request command."""

import pytest
from unittest.mock import patch, MagicMock
import subprocess

from boxctl.cli import cmd_request, main


class FakeArgs:
    """Fake args object for testing."""

    def __init__(self, capability, searched=None, context=None):
        self.capability = capability
        self.searched = searched
        self.context = context


class TestCmdRequest:
    """Tests for cmd_request function."""

    def test_returns_2_when_platform_unknown(self, tmp_path, monkeypatch, capsys):
        """Returns exit 2 when platform cannot be determined."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        with patch("boxctl.core.config.detect_platform_from_remote", return_value=None):
            args = FakeArgs(capability="Test capability")
            result = cmd_request(args)

        assert result == 2
        captured = capsys.readouterr()
        assert "Could not determine issue platform" in captured.err

    def test_returns_2_when_gh_missing(self, tmp_path, monkeypatch, capsys):
        """Returns exit 2 when gh CLI not found."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: github")

        with patch("shutil.which", return_value=None):
            args = FakeArgs(capability="Test capability")
            result = cmd_request(args)

        assert result == 2
        captured = capsys.readouterr()
        assert "gh CLI not found" in captured.err

    def test_returns_2_when_glab_missing(self, tmp_path, monkeypatch, capsys):
        """Returns exit 2 when glab CLI not found."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: gitlab")

        with patch("shutil.which", return_value=None):
            args = FakeArgs(capability="Test capability")
            result = cmd_request(args)

        assert result == 2
        captured = capsys.readouterr()
        assert "glab CLI not found" in captured.err

    def test_creates_github_issue(self, tmp_path, monkeypatch, capsys):
        """Creates GitHub issue with correct format."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: github")

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="https://github.com/user/repo/issues/123\n",
                    stderr="",
                    returncode=0,
                )

                args = FakeArgs(
                    capability="Check Redis replication lag",
                    searched="redis replication, redis lag",
                    context="Debugging slow API responses",
                )
                result = cmd_request(args)

        assert result == 0

        # Verify gh was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "gh"
        assert call_args[1] == "issue"
        assert call_args[2] == "create"
        assert "--title" in call_args
        assert "Script request: Check Redis replication lag" in call_args
        assert "--label" in call_args
        assert "script-request" in call_args

    def test_creates_gitlab_issue(self, tmp_path, monkeypatch, capsys):
        """Creates GitLab issue with correct format."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: gitlab")

        with patch("shutil.which", return_value="/usr/bin/glab"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="https://gitlab.com/user/repo/-/issues/123\n",
                    stderr="",
                    returncode=0,
                )

                args = FakeArgs(capability="Check Redis replication lag")
                result = cmd_request(args)

        assert result == 0

        # Verify glab was called correctly
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "glab"
        assert call_args[1] == "issue"
        assert call_args[2] == "create"
        assert "--description" in call_args  # GitLab uses --description

    def test_body_includes_all_fields(self, tmp_path, monkeypatch):
        """Issue body includes capability, searches, and context."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: github")

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="https://github.com/user/repo/issues/123\n",
                    stderr="",
                    returncode=0,
                )

                args = FakeArgs(
                    capability="Check Redis replication lag",
                    searched="redis replication, redis lag",
                    context="Debugging slow API responses",
                )
                cmd_request(args)

        call_args = mock_run.call_args[0][0]
        body_idx = call_args.index("--body") + 1
        body = call_args[body_idx]

        assert "## Requested Capability" in body
        assert "Check Redis replication lag" in body
        assert "## Searches Tried" in body
        assert "redis replication, redis lag" in body
        assert "## Investigation Context" in body
        assert "Debugging slow API responses" in body
        assert "Filed by LLM agent via `boxctl request`" in body

    def test_body_omits_optional_fields(self, tmp_path, monkeypatch):
        """Issue body omits sections when optional fields not provided."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: github")

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    stdout="https://github.com/user/repo/issues/123\n",
                    stderr="",
                    returncode=0,
                )

                args = FakeArgs(capability="Check Redis replication lag")
                cmd_request(args)

        call_args = mock_run.call_args[0][0]
        body_idx = call_args.index("--body") + 1
        body = call_args[body_idx]

        assert "## Requested Capability" in body
        assert "## Searches Tried" not in body
        assert "## Investigation Context" not in body

    def test_returns_1_on_api_error(self, tmp_path, monkeypatch, capsys):
        """Returns exit 1 when issue creation fails."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".boxctl.yaml").write_text("issue_platform: github")

        with patch("shutil.which", return_value="/usr/bin/gh"):
            with patch("subprocess.run") as mock_run:
                mock_run.side_effect = subprocess.CalledProcessError(
                    1, "gh", stderr="Authentication required"
                )

                args = FakeArgs(capability="Test capability")
                result = cmd_request(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "Error creating issue" in captured.err


class TestRequestViaCLI:
    """Tests for request command via main() entry point."""

    def test_request_help(self, capsys):
        """Request command shows help."""
        with pytest.raises(SystemExit) as exc_info:
            main(["request", "--help"])

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "capability" in captured.out
        assert "--searched" in captured.out
        assert "--context" in captured.out

    def test_request_requires_capability(self, capsys):
        """Request command requires capability argument."""
        with pytest.raises(SystemExit) as exc_info:
            main(["request"])

        assert exc_info.value.code != 0
