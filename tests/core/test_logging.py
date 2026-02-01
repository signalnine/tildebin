"""Tests for logging module."""

import json
import pytest
from datetime import date
from pathlib import Path

from boxctl.core.logging import ScriptLogger, get_log_path, query_logs


class TestGetLogPath:
    """Tests for get_log_path function."""

    def test_returns_path_with_date_and_script(self, tmp_path, monkeypatch):
        """Returns path in format {base}/{date}/{script}.jsonl."""
        monkeypatch.setenv("HOME", str(tmp_path))

        path = get_log_path("disk_health")

        today = date.today().isoformat()
        assert path == tmp_path / "var" / "log" / "boxctl" / today / "disk_health.jsonl"

    def test_custom_base_path(self, tmp_path):
        """Accepts custom base path."""
        path = get_log_path("disk_health", base_path=tmp_path / "logs")

        today = date.today().isoformat()
        assert path == tmp_path / "logs" / today / "disk_health.jsonl"


class TestScriptLogger:
    """Tests for ScriptLogger class."""

    def test_logs_to_file(self, tmp_path):
        """Writes log entries to JSONL file."""
        log_path = tmp_path / "test.jsonl"
        logger = ScriptLogger("test_script", log_path=log_path)

        logger.info("Test message")
        logger.close()

        content = log_path.read_text()
        entry = json.loads(content.strip())
        assert entry["level"] == "info"
        assert entry["message"] == "Test message"
        assert entry["script"] == "test_script"

    def test_logs_multiple_levels(self, tmp_path):
        """Logs debug, info, warning, error levels."""
        log_path = tmp_path / "test.jsonl"
        logger = ScriptLogger("test_script", log_path=log_path)

        logger.debug("Debug msg")
        logger.info("Info msg")
        logger.warning("Warning msg")
        logger.error("Error msg")
        logger.close()

        lines = log_path.read_text().strip().split("\n")
        assert len(lines) == 4

        levels = [json.loads(line)["level"] for line in lines]
        assert levels == ["debug", "info", "warning", "error"]

    def test_logs_include_timestamp(self, tmp_path):
        """Log entries include timestamp."""
        log_path = tmp_path / "test.jsonl"
        logger = ScriptLogger("test_script", log_path=log_path)

        logger.info("Test")
        logger.close()

        entry = json.loads(log_path.read_text().strip())
        assert "timestamp" in entry
        assert "T" in entry["timestamp"]  # ISO format

    def test_logs_extra_data(self, tmp_path):
        """Log entries can include extra data."""
        log_path = tmp_path / "test.jsonl"
        logger = ScriptLogger("test_script", log_path=log_path)

        logger.info("Disk check", disk="/dev/sda", status="PASSED")
        logger.close()

        entry = json.loads(log_path.read_text().strip())
        assert entry["disk"] == "/dev/sda"
        assert entry["status"] == "PASSED"

    def test_creates_parent_directories(self, tmp_path):
        """Creates parent directories if they don't exist."""
        log_path = tmp_path / "deep" / "nested" / "test.jsonl"
        logger = ScriptLogger("test_script", log_path=log_path)

        logger.info("Test")
        logger.close()

        assert log_path.exists()

    def test_context_manager(self, tmp_path):
        """Works as context manager."""
        log_path = tmp_path / "test.jsonl"

        with ScriptLogger("test_script", log_path=log_path) as logger:
            logger.info("Test message")

        assert log_path.exists()
        entry = json.loads(log_path.read_text().strip())
        assert entry["message"] == "Test message"


class TestQueryLogs:
    """Tests for query_logs function."""

    def test_queries_by_date(self, tmp_path):
        """Queries logs from specific date."""
        # Create log file for today
        today = date.today().isoformat()
        log_dir = tmp_path / today
        log_dir.mkdir(parents=True)
        log_file = log_dir / "test.jsonl"
        log_file.write_text(
            '{"timestamp": "2025-01-15T10:00:00", "level": "info", "message": "Test"}\n'
        )

        results = query_logs(base_path=tmp_path, script="test")

        assert len(results) == 1
        assert results[0]["message"] == "Test"

    def test_filters_by_level(self, tmp_path):
        """Filters logs by minimum level."""
        today = date.today().isoformat()
        log_dir = tmp_path / today
        log_dir.mkdir(parents=True)
        log_file = log_dir / "test.jsonl"
        log_file.write_text(
            '{"level": "debug", "message": "Debug"}\n'
            '{"level": "info", "message": "Info"}\n'
            '{"level": "warning", "message": "Warning"}\n'
            '{"level": "error", "message": "Error"}\n'
        )

        results = query_logs(base_path=tmp_path, script="test", min_level="warning")

        assert len(results) == 2
        levels = [r["level"] for r in results]
        assert "debug" not in levels
        assert "info" not in levels

    def test_returns_empty_for_no_logs(self, tmp_path):
        """Returns empty list when no logs found."""
        results = query_logs(base_path=tmp_path, script="nonexistent")
        assert results == []

    def test_limits_results(self, tmp_path):
        """Limits number of results."""
        today = date.today().isoformat()
        log_dir = tmp_path / today
        log_dir.mkdir(parents=True)
        log_file = log_dir / "test.jsonl"
        log_file.write_text(
            '{"level": "info", "message": "1"}\n'
            '{"level": "info", "message": "2"}\n'
            '{"level": "info", "message": "3"}\n'
        )

        results = query_logs(base_path=tmp_path, script="test", limit=2)

        assert len(results) == 2
