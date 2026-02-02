"""Tests for kernel_config script."""

import json
import pytest
from unittest.mock import patch, MagicMock

from boxctl.core.output import Output


class TestKernelConfig:
    """Tests for kernel_config script."""

    def test_no_proc_sys_returns_error(self, mock_context):
        """Returns exit code 2 when /proc/sys doesn't exist."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False
            exit_code = kernel_config.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_all_parameters_pass(self, mock_context):
        """Returns 0 when all parameters meet recommendations."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open:

            mock_exists.return_value = True

            # Mock sysctl reads to return expected values
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)

                # Return values that match the baseline
                values = {
                    "/proc/sys/net/ipv4/tcp_syncookies": "1",
                    "/proc/sys/net/ipv4/conf/all/rp_filter": "1",
                    "/proc/sys/net/ipv4/conf/default/rp_filter": "1",
                    "/proc/sys/kernel/randomize_va_space": "2",
                    "/proc/sys/kernel/dmesg_restrict": "1",
                    "/proc/sys/fs/protected_hardlinks": "1",
                    "/proc/sys/fs/protected_symlinks": "1",
                }
                mock_file.read.return_value = values.get(path, "1")
                return mock_file

            mock_open.side_effect = open_side_effect

            # Test with a specific param to keep it simple
            exit_code = kernel_config.run(
                ["--param", "net.ipv4.tcp_syncookies"], output, ctx
            )

        assert exit_code == 0
        assert output.data["summary"]["failed"] == 0

    def test_failed_parameter_returns_one(self, mock_context):
        """Returns 1 when a parameter fails the check."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open:

            mock_exists.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                # tcp_syncookies is 0 (should be 1)
                mock_file.read.return_value = "0"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_config.run(
                ["--param", "net.ipv4.tcp_syncookies"], output, ctx
            )

        assert exit_code == 1
        assert output.data["summary"]["failed"] > 0

    def test_security_profile(self, mock_context):
        """Test security profile selection."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open:

            mock_exists.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_config.run(["--profile", "security"], output, ctx)

        # Security profile should check security-related params
        assert output.data["summary"]["total"] > 0

    def test_performance_profile(self, mock_context):
        """Test performance profile selection."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open:

            mock_exists.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                # Return high values for performance params
                if "somaxconn" in path:
                    mock_file.read.return_value = "65535"
                elif "file-max" in path:
                    mock_file.read.return_value = "10000000"
                else:
                    mock_file.read.return_value = "100000"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_config.run(["--profile", "performance"], output, ctx)

        assert output.data["summary"]["total"] > 0

    def test_json_output_format(self, mock_context, capsys):
        """Test JSON output format."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open:

            mock_exists.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_config.run(
                ["--format", "json", "--param", "net.ipv4.tcp_syncookies"],
                output,
                ctx,
            )

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "results" in result
        assert "summary" in result

    def test_show_fixes(self, mock_context, capsys):
        """Test --show-fixes generates fix commands."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open:

            mock_exists.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = "0"  # Wrong value
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_config.run(
                ["--show-fixes", "--param", "net.ipv4.tcp_syncookies"],
                output,
                ctx,
            )

        captured = capsys.readouterr()
        assert "sysctl -w" in captured.out

    def test_compare_values_equal(self, mock_context):
        """Test compare_values with equal comparison."""
        from scripts.baremetal import kernel_config

        match, _ = kernel_config.compare_values("1", "1", "eq")
        assert match is True

        match, _ = kernel_config.compare_values("2", "1", "eq")
        assert match is False

    def test_compare_values_greater_equal(self, mock_context):
        """Test compare_values with >= comparison."""
        from scripts.baremetal import kernel_config

        match, _ = kernel_config.compare_values("10", "5", "ge")
        assert match is True

        match, _ = kernel_config.compare_values("5", "5", "ge")
        assert match is True

        match, _ = kernel_config.compare_values("3", "5", "ge")
        assert match is False

    def test_compare_values_less_equal(self, mock_context):
        """Test compare_values with <= comparison."""
        from scripts.baremetal import kernel_config

        match, _ = kernel_config.compare_values("5", "10", "le")
        assert match is True

        match, _ = kernel_config.compare_values("10", "10", "le")
        assert match is True

        match, _ = kernel_config.compare_values("15", "10", "le")
        assert match is False

    def test_skipped_parameters(self, mock_context):
        """Test handling of non-existent parameters."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open:

            mock_exists.return_value = True
            mock_open.side_effect = FileNotFoundError("Not found")

            exit_code = kernel_config.run(
                ["--param", "net.ipv4.tcp_syncookies"], output, ctx
            )

        # Skipped params don't cause failure
        assert output.data["summary"]["skipped"] > 0

    def test_invalid_param_filter(self, mock_context):
        """Test filtering to non-existent param returns error."""
        from scripts.baremetal import kernel_config

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True

            exit_code = kernel_config.run(
                ["--param", "nonexistent.param"], output, ctx
            )

        assert exit_code == 2
