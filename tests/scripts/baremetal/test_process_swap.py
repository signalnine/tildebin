"""Tests for process_swap script."""

import pytest

from boxctl.core.output import Output


class TestProcessSwap:
    """Tests for process_swap script."""

    def test_proc_not_available_returns_error(self, mock_context, monkeypatch):
        """Returns exit code 2 when /proc is not available."""
        from scripts.baremetal import process_swap

        # Mock os.path.isdir to return False for /proc
        monkeypatch.setattr("os.path.isdir", lambda p: False if p == "/proc" else True)

        ctx = mock_context()
        output = Output()

        exit_code = process_swap.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("/proc" in e for e in output.errors)

    def test_no_processes_with_swap(self, mock_context, monkeypatch):
        """Returns 0 when no processes have swap usage."""
        from scripts.baremetal import process_swap

        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr("os.listdir", lambda p: [] if p == "/proc" else [])

        ctx = mock_context()
        output = Output()

        exit_code = process_swap.run([], output, ctx)

        assert exit_code == 0
        assert output.data["processes_with_swap"] == 0
        assert output.data["high_swap_count"] == 0

    def test_invalid_top_argument(self, mock_context, monkeypatch):
        """Returns exit code 2 for invalid --top argument."""
        from scripts.baremetal import process_swap

        monkeypatch.setattr("os.path.isdir", lambda p: True)

        ctx = mock_context()
        output = Output()

        exit_code = process_swap.run(["--top", "-1"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_swap_threshold(self, mock_context, monkeypatch):
        """Returns exit code 2 for invalid --swap-threshold."""
        from scripts.baremetal import process_swap

        monkeypatch.setattr("os.path.isdir", lambda p: True)

        ctx = mock_context()
        output = Output()

        exit_code = process_swap.run(["--swap-threshold", "-100"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_invalid_ratio_threshold(self, mock_context, monkeypatch):
        """Returns exit code 2 for invalid --ratio-threshold."""
        from scripts.baremetal import process_swap

        monkeypatch.setattr("os.path.isdir", lambda p: True)

        ctx = mock_context()
        output = Output()

        exit_code = process_swap.run(["--ratio-threshold", "150"], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0

    def test_format_size_function(self, mock_context):
        """Test the format_size helper function."""
        from scripts.baremetal.process_swap import format_size

        assert format_size(512) == "512 KB"
        assert format_size(1024) == "1.0 MB"
        assert format_size(1536) == "1.5 MB"
        assert format_size(1024 * 1024) == "1.0 GB"
        assert format_size(1024 * 1024 * 2) == "2.0 GB"

    def test_parse_status_value(self, mock_context):
        """Test parsing values from /proc/[pid]/status."""
        from scripts.baremetal.process_swap import parse_status_value

        assert parse_status_value("1024 kB") == 1024
        assert parse_status_value("0 kB") == 0
        assert parse_status_value("  512 kB  ") == 512
        assert parse_status_value("invalid") == 0
        assert parse_status_value("") == 0

    def test_output_includes_thresholds(self, mock_context, monkeypatch):
        """Output includes threshold configuration."""
        from scripts.baremetal import process_swap

        monkeypatch.setattr("os.path.isdir", lambda p: True)
        monkeypatch.setattr("os.listdir", lambda p: [] if p == "/proc" else [])

        ctx = mock_context()
        output = Output()

        exit_code = process_swap.run(
            ["--swap-threshold", "50000", "--ratio-threshold", "75"],
            output,
            ctx
        )

        assert exit_code == 0
        assert output.data["swap_threshold_kb"] == 50000
        assert output.data["ratio_threshold_pct"] == 75.0
