"""Tests for module_params script."""

import json
import pytest
from unittest.mock import patch, MagicMock

from boxctl.core.output import Output


class TestModuleParams:
    """Tests for module_params script."""

    def test_no_sys_module_returns_error(self, mock_context):
        """Returns exit code 2 when /sys/module doesn't exist."""
        from scripts.baremetal import module_params

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.isdir") as mock_isdir:
            mock_isdir.return_value = False
            exit_code = module_params.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_no_modules_found(self, mock_context):
        """Returns 0 when no modules with parameters found."""
        from scripts.baremetal import module_params

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.isdir") as mock_isdir, \
             patch("os.listdir") as mock_listdir:

            mock_isdir.return_value = True
            mock_listdir.return_value = []  # No modules

            exit_code = module_params.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_modules"] == 0

    def test_modules_scanned(self, mock_context):
        """Test scanning modules and their parameters."""
        from scripts.baremetal import module_params

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.isdir") as mock_isdir, \
             patch("os.listdir") as mock_listdir, \
             patch("os.path.isfile") as mock_isfile, \
             patch("builtins.open", create=True) as mock_open:

            def isdir_side_effect(path):
                return path in [
                    "/sys/module",
                    "/sys/module/nvme",
                    "/sys/module/nvme/parameters",
                ]

            mock_isdir.side_effect = isdir_side_effect

            def listdir_side_effect(path):
                if path == "/sys/module":
                    return ["nvme"]
                elif path == "/sys/module/nvme/parameters":
                    return ["io_queue_depth"]
                elif path == "/sys/module/nvme/holders":
                    return []
                return []

            mock_listdir.side_effect = listdir_side_effect
            mock_isfile.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                if "io_queue_depth" in path:
                    mock_file.read.return_value = "1024"
                elif "version" in path:
                    mock_file.read.return_value = "1.0"
                elif "refcount" in path:
                    mock_file.read.return_value = "2"
                else:
                    mock_file.read.return_value = ""
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = module_params.run([], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_modules"] == 1
        assert output.data["summary"]["total_parameters"] == 1

    def test_baseline_comparison_match(self, mock_context, tmp_path):
        """Test baseline comparison when parameters match."""
        from scripts.baremetal import module_params
        from io import StringIO

        ctx = mock_context(tools_available=[])
        output = Output()

        # Create baseline file
        baseline = {"nvme": {"io_queue_depth": "1024"}}
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(json.dumps(baseline))

        real_open = open  # Save reference before patching

        with patch("os.path.isdir") as mock_isdir, \
             patch("os.listdir") as mock_listdir, \
             patch("os.path.isfile") as mock_isfile, \
             patch("scripts.baremetal.module_params.open", create=True) as mock_open:

            def isdir_side_effect(path):
                return path in [
                    "/sys/module",
                    "/sys/module/nvme",
                    "/sys/module/nvme/parameters",
                ]

            mock_isdir.side_effect = isdir_side_effect

            def listdir_side_effect(path):
                if path == "/sys/module":
                    return ["nvme"]
                elif path == "/sys/module/nvme/parameters":
                    return ["io_queue_depth"]
                return []

            mock_listdir.side_effect = listdir_side_effect
            mock_isfile.return_value = True

            def open_side_effect(path, *args, **kwargs):
                # Handle baseline file with real open
                if str(baseline_file) in str(path):
                    return real_open(baseline_file, *args, **kwargs)

                # Mock /sys files
                if isinstance(path, str) and path.startswith("/sys/"):
                    if "io_queue_depth" in path:
                        return StringIO("1024")
                    return StringIO("")

                return real_open(path, *args, **kwargs)

            mock_open.side_effect = open_side_effect

            exit_code = module_params.run(
                ["--baseline", str(baseline_file)], output, ctx
            )

        assert exit_code == 0
        assert output.data["summary"]["mismatches"] == 0

    def test_baseline_comparison_mismatch(self, mock_context, tmp_path):
        """Test baseline comparison when parameters mismatch."""
        from scripts.baremetal import module_params
        from io import StringIO

        ctx = mock_context(tools_available=[])
        output = Output()

        # Create baseline file with different value
        baseline = {"nvme": {"io_queue_depth": "2048"}}  # Expects 2048
        baseline_file = tmp_path / "baseline.json"
        baseline_file.write_text(json.dumps(baseline))

        real_open = open  # Save reference before patching

        with patch("os.path.isdir") as mock_isdir, \
             patch("os.listdir") as mock_listdir, \
             patch("os.path.isfile") as mock_isfile, \
             patch("scripts.baremetal.module_params.open", create=True) as mock_open:

            def isdir_side_effect(path):
                return path in [
                    "/sys/module",
                    "/sys/module/nvme",
                    "/sys/module/nvme/parameters",
                ]

            mock_isdir.side_effect = isdir_side_effect

            def listdir_side_effect(path):
                if path == "/sys/module":
                    return ["nvme"]
                elif path == "/sys/module/nvme/parameters":
                    return ["io_queue_depth"]
                return []

            mock_listdir.side_effect = listdir_side_effect
            mock_isfile.return_value = True

            def open_side_effect(path, *args, **kwargs):
                # Handle baseline file with real open
                if str(baseline_file) in str(path):
                    return real_open(baseline_file, *args, **kwargs)

                # Mock /sys files
                if isinstance(path, str) and path.startswith("/sys/"):
                    if "io_queue_depth" in path:
                        return StringIO("1024")  # Actual is 1024
                    return StringIO("")

                return real_open(path, *args, **kwargs)

            mock_open.side_effect = open_side_effect

            exit_code = module_params.run(
                ["--baseline", str(baseline_file)], output, ctx
            )

        assert exit_code == 1
        assert output.data["summary"]["mismatches"] == 1

    def test_module_filter(self, mock_context):
        """Test filtering modules by name pattern."""
        from scripts.baremetal import module_params

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.isdir") as mock_isdir, \
             patch("os.listdir") as mock_listdir, \
             patch("os.path.isfile") as mock_isfile, \
             patch("builtins.open", create=True) as mock_open:

            def isdir_side_effect(path):
                return path in [
                    "/sys/module",
                    "/sys/module/nvme",
                    "/sys/module/nvme/parameters",
                    "/sys/module/ext4",
                    "/sys/module/ext4/parameters",
                ]

            mock_isdir.side_effect = isdir_side_effect

            def listdir_side_effect(path):
                if path == "/sys/module":
                    return ["nvme", "ext4"]
                elif path == "/sys/module/nvme/parameters":
                    return ["io_queue_depth"]
                elif path == "/sys/module/ext4/parameters":
                    return ["commit"]
                return []

            mock_listdir.side_effect = listdir_side_effect
            mock_isfile.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = "100"
                return mock_file

            mock_open.side_effect = open_side_effect

            # Filter to only nvme
            exit_code = module_params.run(["--module", "nvme"], output, ctx)

        assert exit_code == 0
        assert output.data["summary"]["total_modules"] == 1
        assert output.data["modules"][0]["name"] == "nvme"

    def test_json_output_format(self, mock_context, capsys):
        """Test JSON output format."""
        from scripts.baremetal import module_params

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.isdir") as mock_isdir, \
             patch("os.listdir") as mock_listdir:

            mock_isdir.return_value = True
            mock_listdir.return_value = []

            exit_code = module_params.run(["--format", "json"], output, ctx)

        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "summary" in result
        assert "modules" in result

    def test_generate_baseline(self, mock_context, capsys):
        """Test --generate-baseline outputs JSON baseline."""
        from scripts.baremetal import module_params

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.isdir") as mock_isdir, \
             patch("os.listdir") as mock_listdir, \
             patch("os.path.isfile") as mock_isfile, \
             patch("builtins.open", create=True) as mock_open:

            def isdir_side_effect(path):
                return path in [
                    "/sys/module",
                    "/sys/module/test",
                    "/sys/module/test/parameters",
                ]

            mock_isdir.side_effect = isdir_side_effect

            def listdir_side_effect(path):
                if path == "/sys/module":
                    return ["test"]
                elif path == "/sys/module/test/parameters":
                    return ["param1"]
                return []

            mock_listdir.side_effect = listdir_side_effect
            mock_isfile.return_value = True

            def open_side_effect(path, *args, **kwargs):
                mock_file = MagicMock()
                mock_file.__enter__ = MagicMock(return_value=mock_file)
                mock_file.__exit__ = MagicMock(return_value=False)
                mock_file.read.return_value = "value1"
                return mock_file

            mock_open.side_effect = open_side_effect

            exit_code = module_params.run(["--generate-baseline"], output, ctx)

        assert exit_code == 0
        captured = capsys.readouterr()
        baseline = json.loads(captured.out)
        assert "test" in baseline
        assert baseline["test"]["param1"] == "value1"

    def test_invalid_regex_returns_error(self, mock_context):
        """Test invalid regex pattern returns error."""
        from scripts.baremetal import module_params

        ctx = mock_context(tools_available=[])
        output = Output()

        with patch("os.path.isdir") as mock_isdir:
            mock_isdir.return_value = True
            exit_code = module_params.run(["--module", "[invalid"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
