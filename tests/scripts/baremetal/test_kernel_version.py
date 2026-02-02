"""Tests for kernel_version script."""

import json
import pytest
from unittest.mock import patch, MagicMock

from boxctl.core.output import Output


class TestKernelVersion:
    """Tests for kernel_version script."""

    def test_missing_uname_returns_error(self, mock_context):
        """Returns exit code 2 when uname not available."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = kernel_version.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_modern_kernel_no_issues(self, mock_context):
        """Returns 0 for modern kernel with no issues."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-a"): "Linux host 5.15.0-generic #1 SMP x86_64 GNU/Linux",
                ("uname", "-r"): "5.15.0-generic",
                ("uname", "-v"): "#1 SMP Mon Jan 1 00:00:00 UTC 2024",
                ("uname", "-m"): "x86_64",
                ("uname", "-s"): "Linux",
            },
        )
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "version" in path:
                    mock_file.read.return_value = "Linux version 5.15.0-generic"
                elif "cmdline" in path:
                    mock_file.read.return_value = "root=/dev/sda1 security=apparmor"
                else:
                    mock_file.read.return_value = ""
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_version.run([], output, ctx)

        assert exit_code == 0
        assert output.data["kernel"]["release"] == "5.15.0-generic"

    def test_old_kernel_returns_warning(self, mock_context):
        """Returns 1 for very old kernel (< 3.x)."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-a"): "Linux host 2.6.32-generic #1 SMP x86_64 GNU/Linux",
                ("uname", "-r"): "2.6.32-generic",
                ("uname", "-v"): "#1 SMP",
                ("uname", "-m"): "x86_64",
                ("uname", "-s"): "Linux",
            },
        )
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "version" in path:
                    mock_file.read.return_value = "Linux version 2.6.32"
                elif "cmdline" in path:
                    mock_file.read.return_value = "root=/dev/sda1"
                else:
                    mock_file.read.return_value = ""
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_version.run([], output, ctx)

        assert exit_code == 1
        assert any(i["severity"] == "WARNING" for i in output.data["issues"])
        assert any("old kernel" in i["message"].lower() for i in output.data["issues"])

    def test_debug_options_warning(self, mock_context):
        """Returns 1 when debug options found in cmdline."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-a"): "Linux host 5.15.0-generic #1 SMP x86_64 GNU/Linux",
                ("uname", "-r"): "5.15.0-generic",
                ("uname", "-v"): "#1 SMP",
                ("uname", "-m"): "x86_64",
                ("uname", "-s"): "Linux",
            },
        )
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "version" in path:
                    mock_file.read.return_value = "Linux version 5.15.0"
                elif "cmdline" in path:
                    # Debug option that should trigger warning
                    mock_file.read.return_value = "root=/dev/sda1 nokaslr security=apparmor"
                else:
                    mock_file.read.return_value = ""
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_version.run([], output, ctx)

        assert exit_code == 1
        assert any("nokaslr" in i["message"] for i in output.data["issues"])

    def test_json_output_format(self, mock_context, capsys):
        """Test JSON output format."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-a"): "Linux host 5.15.0 x86_64",
                ("uname", "-r"): "5.15.0",
                ("uname", "-v"): "#1 SMP",
                ("uname", "-m"): "x86_64",
                ("uname", "-s"): "Linux",
            },
        )
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "cmdline" in path:
                    mock_file.read.return_value = "root=/dev/sda1 security=selinux"
                else:
                    mock_file.read.return_value = "Linux version 5.15.0"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_version.run(["--format", "json"], output, ctx)

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "kernel" in result
        assert "issues" in result
        assert "release" in result["kernel"]

    def test_verbose_output(self, mock_context, capsys):
        """Test verbose output includes additional details."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-a"): "Linux host 5.15.0-generic x86_64 GNU/Linux",
                ("uname", "-r"): "5.15.0-generic",
                ("uname", "-v"): "#1 SMP Mon Jan 1 00:00:00 UTC 2024",
                ("uname", "-m"): "x86_64",
                ("uname", "-s"): "Linux",
            },
        )
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "cmdline" in path:
                    mock_file.read.return_value = "root=/dev/sda1 security=apparmor"
                else:
                    mock_file.read.return_value = "Linux version 5.15.0"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_version.run(["--verbose"], output, ctx)

        captured = capsys.readouterr()
        assert "Architecture" in captured.out
        assert "x86_64" in captured.out

    def test_warn_only_suppresses_normal_output(self, mock_context, capsys):
        """Test --warn-only suppresses normal output."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-a"): "Linux host 5.15.0 x86_64",
                ("uname", "-r"): "5.15.0",
                ("uname", "-v"): "#1 SMP",
                ("uname", "-m"): "x86_64",
                ("uname", "-s"): "Linux",
            },
        )
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "cmdline" in path:
                    mock_file.read.return_value = "root=/dev/sda1 security=apparmor"
                else:
                    mock_file.read.return_value = "Linux version 5.15.0"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_version.run(["--warn-only"], output, ctx)

        captured = capsys.readouterr()
        # Should not show "Kernel version:" header in warn-only mode
        assert "Kernel version:" not in captured.out

    def test_no_security_module_info(self, mock_context):
        """Test INFO issue when no security module detected."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-a"): "Linux host 5.15.0 x86_64",
                ("uname", "-r"): "5.15.0",
                ("uname", "-v"): "#1 SMP",
                ("uname", "-m"): "x86_64",
                ("uname", "-s"): "Linux",
            },
        )
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "cmdline" in path:
                    # No security module
                    mock_file.read.return_value = "root=/dev/sda1 quiet"
                else:
                    mock_file.read.return_value = "Linux version 5.15.0"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_version.run([], output, ctx)

        # INFO issues don't cause failure
        assert exit_code == 0
        assert any(
            "security module" in i["message"].lower()
            for i in output.data["issues"]
            if i["severity"] == "INFO"
        )

    def test_kernel_info_structure(self, mock_context):
        """Test kernel info structure in output."""
        from scripts.baremetal import kernel_version

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-a"): "Linux testhost 5.15.0 x86_64",
                ("uname", "-r"): "5.15.0",
                ("uname", "-v"): "#1 SMP",
                ("uname", "-m"): "x86_64",
                ("uname", "-s"): "Linux",
            },
        )
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "cmdline" in path:
                    mock_file.read.return_value = "root=/dev/sda1 security=apparmor"
                else:
                    mock_file.read.return_value = "Linux version 5.15.0"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_version.run([], output, ctx)

        # Verify kernel info structure
        assert "kernel" in output.data
        kernel = output.data["kernel"]
        assert kernel["release"] == "5.15.0"
        assert kernel["architecture"] == "x86_64"
        assert kernel["kernel_name"] == "Linux"
        assert "cmdline" in kernel
