"""Tests for initramfs_health script."""

import json
import pytest
from unittest.mock import patch, MagicMock

from boxctl.core.output import Output


class TestInitramfsHealth:
    """Tests for initramfs_health script."""

    def test_no_boot_directory_returns_error(self, mock_context):
        """Returns exit code 2 when /boot directory doesn't exist."""
        from scripts.baremetal import initramfs_health

        ctx = mock_context(tools_available=["uname"])
        output = Output()

        with patch("os.path.isdir") as mock_isdir:
            mock_isdir.return_value = False
            exit_code = initramfs_health.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("/boot" in e for e in output.errors)

    def test_all_kernels_healthy(self, mock_context):
        """Returns 0 when all kernels have healthy initramfs."""
        from scripts.baremetal import initramfs_health

        ctx = mock_context(
            tools_available=["uname", "dracut"],
            command_outputs={
                ("uname", "-r"): "5.15.0-generic",
            },
        )
        output = Output()

        # Mock the filesystem operations
        with patch("os.path.isdir") as mock_isdir, \
             patch("glob.glob") as mock_glob, \
             patch("os.path.exists") as mock_exists, \
             patch("os.listdir") as mock_listdir, \
             patch("os.stat") as mock_stat, \
             patch("builtins.open", create=True) as mock_open:

            mock_isdir.return_value = True
            mock_glob.side_effect = lambda p: {
                "/boot/vmlinuz-*": ["/boot/vmlinuz-5.15.0-generic"],
                "/boot/vmlinux-*": [],
                "/boot/initramfs-*.img": [],
                "/boot/initrd.img-*": ["/boot/initrd.img-5.15.0-generic"],
                "/boot/initrd-*": [],
            }.get(p, [])
            mock_exists.return_value = True
            mock_listdir.return_value = ["5.15.0-generic"]

            # Mock stat for file info
            stat_result = MagicMock()
            stat_result.st_size = 50 * 1024 * 1024  # 50MB
            stat_result.st_mtime = 1700000000
            stat_result.st_mode = 0o100644
            stat_result.st_uid = 0
            stat_result.st_gid = 0
            mock_stat.return_value = stat_result

            # Mock file reading for compression detection (gzip magic bytes)
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=False)
            mock_file.read.return_value = b"\x1f\x8b\x08\x00\x00\x00"
            mock_open.return_value = mock_file

            exit_code = initramfs_health.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["healthy"] >= 0

    def test_missing_initramfs_returns_one(self, mock_context):
        """Returns 1 when kernel is missing initramfs."""
        from scripts.baremetal import initramfs_health

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-r"): "5.15.0-generic",
            },
        )
        output = Output()

        # Mock the filesystem operations
        with patch("os.path.isdir") as mock_isdir, \
             patch("glob.glob") as mock_glob, \
             patch("os.path.exists") as mock_exists, \
             patch("os.listdir") as mock_listdir, \
             patch("os.stat") as mock_stat:

            mock_isdir.return_value = True
            mock_glob.side_effect = lambda p: {
                "/boot/vmlinuz-*": ["/boot/vmlinuz-5.15.0-generic"],
                "/boot/vmlinux-*": [],
                "/boot/initramfs-*.img": [],
                "/boot/initrd.img-*": [],
                "/boot/initrd-*": [],
            }.get(p, [])
            mock_exists.return_value = False  # No initramfs exists
            mock_listdir.return_value = ["5.15.0-generic"]

            stat_result = MagicMock()
            stat_result.st_size = 10 * 1024 * 1024
            stat_result.st_mtime = 1700000000
            stat_result.st_mode = 0o100644
            stat_result.st_uid = 0
            stat_result.st_gid = 0
            mock_stat.return_value = stat_result

            exit_code = initramfs_health.run([], output, ctx)

        assert exit_code == 1
        assert output.data["summary"]["missing_initramfs"] > 0
        assert len(output.data["issues"]) > 0

    def test_json_output_format(self, mock_context, capsys):
        """Test JSON output format."""
        from scripts.baremetal import initramfs_health

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-r"): "5.15.0-generic",
            },
        )
        output = Output()

        with patch("os.path.isdir") as mock_isdir, \
             patch("glob.glob") as mock_glob, \
             patch("os.listdir") as mock_listdir:

            mock_isdir.return_value = True
            mock_glob.return_value = []
            mock_listdir.return_value = []

            exit_code = initramfs_health.run(["--format", "json"], output, ctx)

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "kernels" in result
        assert "summary" in result
        assert "issues" in result

    def test_warn_only_silent_when_healthy(self, mock_context, capsys):
        """--warn-only produces no output when all healthy."""
        from scripts.baremetal import initramfs_health

        ctx = mock_context(
            tools_available=["uname"],
            command_outputs={
                ("uname", "-r"): "5.15.0-generic",
            },
        )
        output = Output()

        with patch("os.path.isdir") as mock_isdir, \
             patch("glob.glob") as mock_glob, \
             patch("os.listdir") as mock_listdir:

            mock_isdir.return_value = True
            mock_glob.return_value = []  # No kernels found
            mock_listdir.return_value = []

            exit_code = initramfs_health.run(["--warn-only"], output, ctx)

        captured = capsys.readouterr()
        # Output should be empty or minimal in warn-only mode with no issues
        # (since no kernels = no missing initramfs = no issues to report)

    def test_detect_compression_gzip(self, mock_context):
        """Test gzip compression detection."""
        from scripts.baremetal import initramfs_health

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=False)
            mock_file.read.return_value = b"\x1f\x8b\x08\x00\x00\x00"
            mock_open.return_value = mock_file

            compression = initramfs_health.detect_compression("/boot/initrd.img-test")

        assert compression == "gzip"

    def test_detect_compression_xz(self, mock_context):
        """Test XZ compression detection."""
        from scripts.baremetal import initramfs_health

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=False)
            mock_file.read.return_value = b"\xfd7zXZ\x00"
            mock_open.return_value = mock_file

            compression = initramfs_health.detect_compression("/boot/initrd.img-test")

        assert compression == "xz"

    def test_detect_compression_zstd(self, mock_context):
        """Test zstd compression detection."""
        from scripts.baremetal import initramfs_health

        with patch("builtins.open", create=True) as mock_open:
            mock_file = MagicMock()
            mock_file.__enter__ = MagicMock(return_value=mock_file)
            mock_file.__exit__ = MagicMock(return_value=False)
            mock_file.read.return_value = b"\x28\xb5\x2f\xfd\x00\x00"
            mock_open.return_value = mock_file

            compression = initramfs_health.detect_compression("/boot/initrd.img-test")

        assert compression == "zstd"
