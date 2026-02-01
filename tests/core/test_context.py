"""Tests for Context execution wrapper."""

import subprocess
import pytest
from boxctl.core.context import Context


class TestContext:
    """Tests for execution context."""

    def test_check_tool_finds_existing(self):
        """check_tool returns True for existing tools."""
        ctx = Context()
        # 'ls' exists on all Unix systems
        assert ctx.check_tool("ls") is True

    def test_check_tool_missing(self):
        """check_tool returns False for missing tools."""
        ctx = Context()
        assert ctx.check_tool("nonexistent_tool_xyz") is False

    def test_run_executes_command(self):
        """run() executes command and returns result."""
        ctx = Context()
        result = ctx.run(["echo", "hello"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_run_captures_stderr(self):
        """run() captures stderr output."""
        ctx = Context()
        result = ctx.run(["ls", "/nonexistent_path_xyz"], check=False)
        assert result.returncode != 0
        assert result.stderr  # Should have error message

    def test_read_file_returns_content(self, tmp_path):
        """read_file() returns file content."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")
        ctx = Context()
        content = ctx.read_file(str(test_file))
        assert content == "test content"

    def test_read_file_raises_on_missing(self):
        """read_file() raises FileNotFoundError for missing files."""
        ctx = Context()
        with pytest.raises(FileNotFoundError):
            ctx.read_file("/nonexistent_file_xyz")

    def test_file_exists_true(self, tmp_path):
        """file_exists() returns True for existing files."""
        test_file = tmp_path / "exists.txt"
        test_file.write_text("content")
        ctx = Context()
        assert ctx.file_exists(str(test_file)) is True

    def test_file_exists_false(self):
        """file_exists() returns False for missing files."""
        ctx = Context()
        assert ctx.file_exists("/nonexistent_xyz") is False

    def test_glob_finds_files(self, tmp_path):
        """glob() finds matching files."""
        (tmp_path / "test1.txt").write_text("1")
        (tmp_path / "test2.txt").write_text("2")
        (tmp_path / "other.py").write_text("3")
        ctx = Context()
        matches = ctx.glob("*.txt", str(tmp_path))
        assert len(matches) == 2
        assert any("test1.txt" in m for m in matches)
        assert any("test2.txt" in m for m in matches)
