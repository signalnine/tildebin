"""Tests for MockContext test helper."""

import pytest
import subprocess


class TestMockContext:
    """Tests for MockContext fixture."""

    def test_check_tool_with_available(self, mock_context):
        """MockContext reports tools as available."""
        ctx = mock_context(tools_available=["smartctl", "lsblk"])
        assert ctx.check_tool("smartctl") is True
        assert ctx.check_tool("lsblk") is True
        assert ctx.check_tool("missing") is False

    def test_run_returns_mocked_output(self, mock_context):
        """MockContext returns configured command outputs."""
        ctx = mock_context(
            tools_available=["echo"],
            command_outputs={
                ("echo", "hello"): "hello\n",
            }
        )
        result = ctx.run(["echo", "hello"])
        assert result.stdout == "hello\n"
        assert result.returncode == 0

    def test_run_tracks_commands(self, mock_context):
        """MockContext tracks which commands were run."""
        ctx = mock_context(
            tools_available=["cmd"],
            command_outputs={
                ("cmd", "arg1"): "output1",
                ("cmd", "arg2"): "output2",
            }
        )
        ctx.run(["cmd", "arg1"])
        ctx.run(["cmd", "arg2"])
        assert ["cmd", "arg1"] in ctx.commands_run
        assert ["cmd", "arg2"] in ctx.commands_run

    def test_read_file_returns_mocked_content(self, mock_context):
        """MockContext returns configured file contents."""
        ctx = mock_context(
            file_contents={
                "/proc/mdstat": "md0 : active raid1 sda1[0] sdb1[1]",
            }
        )
        content = ctx.read_file("/proc/mdstat")
        assert "raid1" in content

    def test_read_file_raises_on_unmocked(self, mock_context):
        """MockContext raises for files not in mock."""
        ctx = mock_context()
        with pytest.raises(FileNotFoundError):
            ctx.read_file("/unmocked/path")

    def test_run_raises_on_unmocked_command(self, mock_context):
        """MockContext raises for commands not in mock."""
        ctx = mock_context(tools_available=["cmd"])
        with pytest.raises(KeyError):
            ctx.run(["cmd", "unknown_args"])

    def test_run_raises_configured_exception(self, mock_context):
        """MockContext can raise configured exceptions."""
        ctx = mock_context(
            tools_available=["cmd"],
            command_outputs={
                ("cmd", "fail"): OSError("Command failed"),
            }
        )
        with pytest.raises(OSError, match="Command failed"):
            ctx.run(["cmd", "fail"])

    def test_file_exists_mocked(self, mock_context):
        """MockContext file_exists returns True for mocked files."""
        ctx = mock_context(
            file_contents={"/etc/test": "content"}
        )
        assert ctx.file_exists("/etc/test") is True
        assert ctx.file_exists("/etc/missing") is False
