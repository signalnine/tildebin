"""Tests for kdump_audit script."""

import json
import pytest
from unittest.mock import patch, MagicMock

from boxctl.core.output import Output


class TestKdumpAudit:
    """Tests for kdump_audit script."""

    def test_no_proc_returns_error(self, mock_context):
        """Returns exit code 2 when /proc doesn't exist."""
        from scripts.baremetal import kdump_audit

        ctx = mock_context(tools_available=["systemctl"])
        output = Output()

        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False
            exit_code = kdump_audit.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_kdump_properly_configured(self, mock_context):
        """Returns 0 when kdump is properly configured."""
        from scripts.baremetal import kdump_audit

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-unit-files", "kdump.service"): "kdump.service enabled",
                ("systemctl", "is-enabled", "kdump.service"): "",
                ("systemctl", "is-active", "kdump.service"): "active",
            },
        )
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open, \
             patch("os.stat") as mock_stat, \
             patch("os.access") as mock_access, \
             patch("os.statvfs") as mock_statvfs, \
             patch("glob.glob") as mock_glob:

            def exists_side_effect(path):
                return path in [
                    "/proc",
                    "/proc/cmdline",
                    "/proc/meminfo",
                    "/var/crash",
                    "/sys/kernel/kexec_crash_loaded",
                ]

            mock_exists.side_effect = exists_side_effect

            # Mock file reads
            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)

                if path == "/proc/cmdline":
                    mock_file.read.return_value = "root=/dev/sda1 crashkernel=256M"
                elif path == "/proc/meminfo":
                    mock_file.read.return_value = "MemTotal:       16384000 kB\n"
                elif path == "/sys/kernel/kexec_crash_loaded":
                    mock_file.read.return_value = "1"
                else:
                    mock_file.read.return_value = ""

                return mock_file

            mock_open.side_effect = open_side_effect

            # Mock stat for dump directory
            stat_result = MagicMock()
            stat_result.st_mode = 0o40755
            mock_stat.return_value = stat_result

            mock_access.return_value = True

            # Mock statvfs for disk space
            statvfs_result = MagicMock()
            statvfs_result.f_frsize = 4096
            statvfs_result.f_blocks = 1000000
            statvfs_result.f_bfree = 500000
            statvfs_result.f_bavail = 450000
            mock_statvfs.return_value = statvfs_result

            mock_glob.return_value = []

            exit_code = kdump_audit.run([], output, ctx)

        assert exit_code == 0

    def test_kdump_not_installed(self, mock_context):
        """Returns 1 when kdump is not installed."""
        from scripts.baremetal import kdump_audit

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-unit-files", "kdump.service"): "",
                ("systemctl", "is-enabled", "kdump.service"): "",
                ("systemctl", "is-active", "kdump.service"): "",
            },
        )
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open, \
             patch("os.stat") as mock_stat, \
             patch("os.access") as mock_access, \
             patch("os.statvfs") as mock_statvfs, \
             patch("glob.glob") as mock_glob:

            def exists_side_effect(path):
                return path in ["/proc", "/proc/cmdline", "/proc/meminfo", "/var/crash"]

            mock_exists.side_effect = exists_side_effect

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)

                if path == "/proc/cmdline":
                    mock_file.read.return_value = "root=/dev/sda1 crashkernel=256M"
                elif path == "/proc/meminfo":
                    mock_file.read.return_value = "MemTotal:       16384000 kB\n"
                else:
                    mock_file.read.return_value = ""

                return mock_file

            mock_open.side_effect = open_side_effect

            stat_result = MagicMock()
            stat_result.st_mode = 0o40755
            mock_stat.return_value = stat_result
            mock_access.return_value = True

            statvfs_result = MagicMock()
            statvfs_result.f_frsize = 4096
            statvfs_result.f_blocks = 1000000
            statvfs_result.f_bfree = 500000
            statvfs_result.f_bavail = 450000
            mock_statvfs.return_value = statvfs_result

            mock_glob.return_value = []

            exit_code = kdump_audit.run([], output, ctx)

        assert exit_code == 1
        assert any(i["severity"] == "CRITICAL" for i in output.data["issues"])
        assert any("not installed" in i["message"] for i in output.data["issues"])

    def test_no_crashkernel_reservation(self, mock_context):
        """Returns 1 when crashkernel is not reserved."""
        from scripts.baremetal import kdump_audit

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-unit-files", "kdump.service"): "kdump.service enabled",
                ("systemctl", "is-enabled", "kdump.service"): "",
                ("systemctl", "is-active", "kdump.service"): "active",
            },
        )
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open, \
             patch("os.stat") as mock_stat, \
             patch("os.access") as mock_access, \
             patch("os.statvfs") as mock_statvfs, \
             patch("glob.glob") as mock_glob:

            def exists_side_effect(path):
                return path in ["/proc", "/proc/cmdline", "/proc/meminfo", "/var/crash"]

            mock_exists.side_effect = exists_side_effect

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)

                if path == "/proc/cmdline":
                    mock_file.read.return_value = "root=/dev/sda1"  # No crashkernel
                elif path == "/proc/meminfo":
                    mock_file.read.return_value = "MemTotal:       16384000 kB\n"
                else:
                    mock_file.read.return_value = ""

                return mock_file

            mock_open.side_effect = open_side_effect

            stat_result = MagicMock()
            stat_result.st_mode = 0o40755
            mock_stat.return_value = stat_result
            mock_access.return_value = True

            statvfs_result = MagicMock()
            statvfs_result.f_frsize = 4096
            statvfs_result.f_blocks = 1000000
            statvfs_result.f_bfree = 500000
            statvfs_result.f_bavail = 450000
            mock_statvfs.return_value = statvfs_result

            mock_glob.return_value = []

            exit_code = kdump_audit.run([], output, ctx)

        assert exit_code == 1
        assert any("crashkernel" in i["message"].lower() for i in output.data["issues"])

    def test_json_output_format(self, mock_context, capsys):
        """Test JSON output format."""
        from scripts.baremetal import kdump_audit

        ctx = mock_context(
            tools_available=["systemctl"],
            command_outputs={
                ("systemctl", "list-unit-files", "kdump.service"): "",
                ("systemctl", "is-enabled", "kdump.service"): "",
                ("systemctl", "is-active", "kdump.service"): "",
            },
        )
        output = Output()

        with patch("os.path.exists") as mock_exists, \
             patch("builtins.open", create=True) as mock_open, \
             patch("os.stat") as mock_stat, \
             patch("os.access") as mock_access, \
             patch("os.statvfs") as mock_statvfs, \
             patch("glob.glob") as mock_glob:

            mock_exists.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = ""
                return mock_file

            mock_open.side_effect = open_side_effect

            stat_result = MagicMock()
            stat_result.st_mode = 0o40755
            mock_stat.return_value = stat_result
            mock_access.return_value = True

            statvfs_result = MagicMock()
            statvfs_result.f_frsize = 4096
            statvfs_result.f_blocks = 1000000
            statvfs_result.f_bfree = 500000
            statvfs_result.f_bavail = 450000
            mock_statvfs.return_value = statvfs_result

            mock_glob.return_value = []

            exit_code = kdump_audit.run(["--format", "json"], output, ctx)

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "service" in result
        assert "crashkernel" in result
        assert "issues" in result

    def test_crashkernel_auto_detection(self, mock_context):
        """Test detection of crashkernel=auto."""
        from scripts.baremetal import kdump_audit

        crashkernel = kdump_audit.check_crashkernel_reservation.__wrapped__() \
            if hasattr(kdump_audit.check_crashkernel_reservation, '__wrapped__') \
            else None

        # Test the function directly with mocking
        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=False)
            mock_file.read.return_value = "root=/dev/sda1 crashkernel=auto quiet"
            mock_open.return_value = mock_file

            result = kdump_audit.check_crashkernel_reservation()

        assert result["reserved"] is True
        assert result["size"] == "auto"
        assert result["parameter"] == "auto"
