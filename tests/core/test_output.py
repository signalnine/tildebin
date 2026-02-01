"""Tests for Output helper."""

import json
import pytest
from boxctl.core.output import Output


class TestOutput:
    """Tests for structured output helper."""

    def test_emit_stores_data(self):
        """emit() stores data for later retrieval."""
        output = Output()
        output.emit({"disks": [{"name": "sda", "status": "ok"}]})
        assert output.data["disks"][0]["name"] == "sda"

    def test_error_stores_message(self):
        """error() stores error messages."""
        output = Output()
        output.error("smartctl not found")
        assert "smartctl not found" in output.errors

    def test_warning_stores_message(self):
        """warning() stores warning messages."""
        output = Output()
        output.warning("disk degraded")
        assert "disk degraded" in output.warnings

    def test_json_format(self):
        """to_json() returns valid JSON string."""
        output = Output()
        output.emit({"test": "value"})
        result = output.to_json()
        parsed = json.loads(result)
        assert parsed["test"] == "value"

    def test_plain_format_with_data(self):
        """to_plain() formats data as readable text."""
        output = Output()
        output.emit({"status": "ok", "count": 5})
        result = output.to_plain()
        assert "status" in result
        assert "ok" in result

    def test_summary_property(self):
        """summary returns first line of plain output."""
        output = Output()
        output.emit({"status": "ok"})
        output.set_summary("All checks passed")
        assert output.summary == "All checks passed"

    def test_summary_from_error(self):
        """summary auto-generates from errors if not set."""
        output = Output()
        output.error("Something failed")
        assert "Something failed" in output.summary

    def test_summary_from_warning(self):
        """summary auto-generates from warnings if no errors."""
        output = Output()
        output.warning("Disk degraded")
        assert "Disk degraded" in output.summary

    def test_emit_merges_data(self):
        """Multiple emit() calls merge data."""
        output = Output()
        output.emit({"key1": "value1"})
        output.emit({"key2": "value2"})
        assert output.data["key1"] == "value1"
        assert output.data["key2"] == "value2"
