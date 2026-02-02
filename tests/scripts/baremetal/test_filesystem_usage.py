#!/usr/bin/env python3
"""Tests for scripts/baremetal/filesystem_usage.py."""

import json
import pytest

from boxctl.core.context import Context
from boxctl.core.output import Output
from scripts.baremetal.filesystem_usage import (
    run,
    parse_size_to_bytes,
    format_bytes
)


class TestFilesystemUsage:
    """Tests for filesystem_usage script."""

    def test_help_output(self):
        """Test --help displays usage information."""
        output = Output()
        context = Context()

        with pytest.raises(SystemExit) as exc_info:
            run(["--help"], output, context)

        assert exc_info.value.code == 0

    def test_parse_size_kilobytes(self):
        """Test parsing kilobyte sizes."""
        assert parse_size_to_bytes("10K") == 10 * 1024
        assert parse_size_to_bytes("1.5K") == int(1.5 * 1024)

    def test_parse_size_megabytes(self):
        """Test parsing megabyte sizes."""
        assert parse_size_to_bytes("100M") == 100 * 1024 * 1024
        assert parse_size_to_bytes("2.5M") == int(2.5 * 1024 * 1024)

    def test_parse_size_gigabytes(self):
        """Test parsing gigabyte sizes."""
        assert parse_size_to_bytes("1G") == 1024 * 1024 * 1024
        assert parse_size_to_bytes("10.5G") == int(10.5 * 1024 * 1024 * 1024)

    def test_parse_size_terabytes(self):
        """Test parsing terabyte sizes."""
        assert parse_size_to_bytes("1T") == 1024 ** 4

    def test_parse_size_bytes(self):
        """Test parsing plain byte values."""
        assert parse_size_to_bytes("1024") == 1024
        assert parse_size_to_bytes("0") == 0

    def test_parse_size_invalid(self):
        """Test parsing invalid size strings."""
        assert parse_size_to_bytes("invalid") == 0
        assert parse_size_to_bytes("") == 0

    def test_format_bytes_small(self):
        """Test formatting small byte values."""
        assert format_bytes(100) == "100B"
        assert format_bytes(0) == "0B"

    def test_format_bytes_kilobytes(self):
        """Test formatting kilobyte values."""
        assert format_bytes(2048) == "2.0K"

    def test_format_bytes_megabytes(self):
        """Test formatting megabyte values."""
        assert format_bytes(5 * 1024 * 1024) == "5.0M"

    def test_format_bytes_gigabytes(self):
        """Test formatting gigabyte values."""
        assert format_bytes(10 * 1024 * 1024 * 1024) == "10.0G"

    def test_format_bytes_terabytes(self):
        """Test formatting terabyte values."""
        assert format_bytes(2 * 1024 ** 4) == "2.0T"

    def test_nonexistent_path(self):
        """Test error for non-existent path."""
        output = Output()
        context = Context()

        result = run(["/nonexistent/path/that/does/not/exist"], output, context)

        assert result == 2
        assert bool(output.errors)

    def test_invalid_depth(self):
        """Test error for invalid depth."""
        output = Output()
        context = Context()

        result = run(["/tmp", "--depth", "-1"], output, context)

        assert result == 2
        assert bool(output.errors)

    def test_invalid_top(self):
        """Test error for invalid top value."""
        output = Output()
        context = Context()

        result = run(["/tmp", "--top", "0"], output, context)

        assert result == 2
        assert bool(output.errors)

    def test_format_json(self):
        """Test JSON output format."""
        output = Output()
        output.emit({
            "path": "/tmp",
            "total_size": "1.0G",
            "entries": [{
                "directory": "/tmp",
                "size_bytes": 1073741824,
                "size_human": "1.0G",
                "percent": 100.0
            }]
        })

        data = output.data
        json_str = json.dumps(data)
        parsed = json.loads(json_str)

        assert "path" in parsed
        assert "entries" in parsed
        assert len(parsed["entries"]) == 1
