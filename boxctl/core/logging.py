"""JSONL logging for script execution."""

import json
import os
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


# Log level ordering
LOG_LEVELS = {"debug": 0, "info": 1, "warning": 2, "error": 3}


def get_log_path(script_name: str, base_path: Path | None = None) -> Path:
    """
    Get the log file path for a script.

    Args:
        script_name: Name of the script (without .py extension)
        base_path: Base directory for logs (default: ~/var/log/boxctl)

    Returns:
        Path to the log file: {base}/{date}/{script}.jsonl
    """
    if base_path is None:
        home = Path(os.environ.get("HOME", "/tmp"))
        base_path = home / "var" / "log" / "boxctl"

    today = date.today().isoformat()
    return base_path / today / f"{script_name}.jsonl"


class ScriptLogger:
    """
    JSONL logger for script execution.

    Writes structured log entries to a JSONL file.
    """

    def __init__(self, script_name: str, log_path: Path | None = None):
        """
        Initialize logger.

        Args:
            script_name: Name of the script being logged
            log_path: Path to log file (default: auto-generated)
        """
        self.script_name = script_name
        self.log_path = log_path or get_log_path(script_name)
        self._file = None

    def _ensure_file(self) -> None:
        """Ensure log file is open."""
        if self._file is None:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.log_path, "a")

    def _log(self, level: str, message: str, **extra: Any) -> None:
        """Write a log entry."""
        self._ensure_file()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "script": self.script_name,
            "message": message,
            **extra,
        }
        self._file.write(json.dumps(entry) + "\n")
        self._file.flush()

    def debug(self, message: str, **extra: Any) -> None:
        """Log debug message."""
        self._log("debug", message, **extra)

    def info(self, message: str, **extra: Any) -> None:
        """Log info message."""
        self._log("info", message, **extra)

    def warning(self, message: str, **extra: Any) -> None:
        """Log warning message."""
        self._log("warning", message, **extra)

    def error(self, message: str, **extra: Any) -> None:
        """Log error message."""
        self._log("error", message, **extra)

    def close(self) -> None:
        """Close the log file."""
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> "ScriptLogger":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()


def query_logs(
    base_path: Path,
    script: str,
    log_date: date | None = None,
    min_level: str = "debug",
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """
    Query log entries.

    Args:
        base_path: Base directory for logs
        script: Script name to query
        log_date: Date to query (default: today)
        min_level: Minimum log level to include
        limit: Maximum number of entries to return

    Returns:
        List of log entries matching criteria
    """
    if log_date is None:
        log_date = date.today()

    log_file = base_path / log_date.isoformat() / f"{script}.jsonl"

    if not log_file.exists():
        return []

    min_level_num = LOG_LEVELS.get(min_level, 0)
    results = []

    with open(log_file) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                entry_level = LOG_LEVELS.get(entry.get("level", "debug"), 0)
                if entry_level >= min_level_num:
                    results.append(entry)
                    if limit and len(results) >= limit:
                        break
            except json.JSONDecodeError:
                continue

    return results
