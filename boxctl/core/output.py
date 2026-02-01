"""Structured output helper for scripts."""

import json
from typing import Any


class Output:
    """Helper for structured script output."""

    def __init__(self):
        self.data: dict[str, Any] = {}
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self._summary: str | None = None

    def emit(self, data: dict[str, Any]) -> None:
        """Store structured output data."""
        self.data.update(data)

    def error(self, message: str) -> None:
        """Record an error message."""
        self.errors.append(message)

    def warning(self, message: str) -> None:
        """Record a warning message."""
        self.warnings.append(message)

    def set_summary(self, summary: str) -> None:
        """Set a one-line summary."""
        self._summary = summary

    @property
    def summary(self) -> str:
        """Get summary or generate from data."""
        if self._summary:
            return self._summary
        if self.errors:
            return f"Error: {self.errors[0]}"
        if self.warnings:
            return f"Warning: {self.warnings[0]}"
        return "ok"

    def to_json(self) -> str:
        """Return data as JSON string."""
        return json.dumps(self.data, indent=2, default=str)

    def to_plain(self) -> str:
        """Return data as plain text."""
        lines = []
        for key, value in self.data.items():
            if isinstance(value, list):
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(f"  - {item}")
                    else:
                        lines.append(f"  - {item}")
            else:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)
