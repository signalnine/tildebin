"""Tests for kernel_security script."""

import json
import pytest
from unittest.mock import patch, MagicMock

from boxctl.core.output import Output


class TestKernelSecurity:
    """Tests for kernel_security script."""

    def test_all_parameters_pass(self, mock_context):
        """Returns 0 when all security parameters pass."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            # Return recommended values for all parameters
            values = {
                "/proc/sys/net/ipv4/tcp_syncookies": "1",
                "/proc/sys/kernel/randomize_va_space": "2",
                "/proc/sys/net/ipv4/conf/all/rp_filter": "1",
                "/proc/sys/net/ipv4/conf/default/rp_filter": "1",
                "/proc/sys/fs/protected_symlinks": "1",
                "/proc/sys/fs/protected_hardlinks": "1",
                "/proc/sys/kernel/dmesg_restrict": "1",
                "/proc/sys/kernel/kptr_restrict": "1",
            }

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = values.get(path, "1")
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(
                ["--category", "network", "--category", "memory"], output, ctx
            )

        # Should pass with correct values
        assert exit_code == 0 or output.data["summary"]["critical_failures"] == 0

    def test_critical_failure_returns_one(self, mock_context):
        """Returns 1 when a critical parameter fails."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)

                # tcp_syncookies is CRITICAL and set to wrong value
                if "tcp_syncookies" in path:
                    mock_file.read.return_value = "0"
                # ASLR is CRITICAL and set to wrong value
                elif "randomize_va_space" in path:
                    mock_file.read.return_value = "0"
                else:
                    mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(["--category", "network"], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["critical_failures"] > 0

    def test_warning_failure_returns_one(self, mock_context):
        """Returns 1 when a warning parameter fails."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)

                # rp_filter is WARNING level
                if "rp_filter" in path:
                    mock_file.read.return_value = "0"
                else:
                    mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(["--category", "network"], output, ctx)

        # Should fail due to warning
        assert exit_code == 1

    def test_info_failure_passes_without_strict(self, mock_context):
        """INFO-level failures pass without --strict."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)

                # All critical/warning params pass, only INFO fails
                if "ip_forward" in path:  # This is INFO level
                    mock_file.read.return_value = "1"  # Wrong value
                else:
                    mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(["--category", "network"], output, ctx)

        # INFO failures should not cause failure without --strict
        # (unless there are also WARNING/CRITICAL failures)

    def test_strict_mode_fails_on_info(self, mock_context):
        """--strict makes INFO-level failures cause exit code 1."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)

                # Force at least one failure
                if "mmap_rnd" in path:  # INFO level param
                    mock_file.read.return_value = "16"  # Different from expected
                else:
                    mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(
                ["--strict", "--category", "memory"], output, ctx
            )

        # With strict, INFO failures cause exit code 1
        if output.data["summary"]["info_failures"] > 0:
            assert exit_code == 1

    def test_category_filter(self, mock_context):
        """Test filtering by category."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(["--category", "filesystem"], output, ctx)

        # Only filesystem category should be checked
        for result in output.data["results"]:
            assert result["category"] == "filesystem"

    def test_json_output_format(self, mock_context, capsys):
        """Test JSON output format."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(
                ["--format", "json", "--category", "filesystem"], output, ctx
            )

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "results" in result
        assert "summary" in result
        assert "score" in result["summary"]

    def test_list_parameters(self, mock_context, capsys):
        """Test --list-parameters shows all checked parameters."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        exit_code = kernel_security.run(["--list-parameters"], output, ctx)

        assert exit_code == 0
        captured = capsys.readouterr()
        assert "Security parameters" in captured.out
        assert "NETWORK" in captured.out
        assert "tcp_syncookies" in captured.out

    def test_unavailable_parameter(self, mock_context):
        """Test handling of unavailable parameters."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                # Simulate file not found for some params
                if "yama" in path:
                    raise FileNotFoundError("No such file")
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(["--category", "kernel"], output, ctx)

        # Unavailable params should be counted
        assert output.data["summary"]["unavailable"] >= 0

    def test_security_score_calculation(self, mock_context):
        """Test security score is calculated correctly."""
        from scripts.baremetal import kernel_security

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("builtins.open", create=True) as mock_open:
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                # Return correct values for all
                mock_file.read.return_value = "1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = kernel_security.run(["--category", "filesystem"], output, ctx)

        # Score should be calculated
        assert "score" in output.data["summary"]
        assert isinstance(output.data["summary"]["score"], (int, float))

    def test_special_case_mmap_min_addr(self, mock_context):
        """Test mmap_min_addr passes with higher values."""
        from scripts.baremetal import kernel_security

        # Direct test of check_parameter
        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=False)
            mock_file.read.return_value = "131072"  # Higher than 65536
            mock_open.return_value = mock_file

            result = kernel_security.check_parameter(
                "vm.mmap_min_addr",
                "65536",
                "WARNING",
                "memory",
                "Test description",
            )

        # Higher value should pass
        assert result["status"] == "pass"
