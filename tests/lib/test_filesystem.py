"""Tests for filesystem utilities."""

import pytest

from boxctl.lib.filesystem import read_file, file_exists, glob_files, FileError


class TestReadFile:
    """Tests for read_file function."""

    def test_reads_file_content(self, mock_context):
        """Returns file content."""
        ctx = mock_context(
            file_contents={"/etc/test": "content\nhere"}
        )

        content = read_file("/etc/test", context=ctx)

        assert content == "content\nhere"

    def test_raises_on_missing_file(self, mock_context):
        """Raises FileError when file doesn't exist."""
        ctx = mock_context(file_contents={})

        with pytest.raises(FileError, match="not found"):
            read_file("/missing/file", context=ctx)

    def test_returns_default_on_missing(self, mock_context):
        """Returns default value when file missing and default provided."""
        ctx = mock_context(file_contents={})

        content = read_file("/missing/file", default="fallback", context=ctx)

        assert content == "fallback"


class TestFileExists:
    """Tests for file_exists function."""

    def test_returns_true_when_exists(self, mock_context):
        """Returns True when file exists."""
        ctx = mock_context(
            file_contents={"/etc/test": "content"}
        )

        assert file_exists("/etc/test", context=ctx) is True

    def test_returns_false_when_missing(self, mock_context):
        """Returns False when file doesn't exist."""
        ctx = mock_context(file_contents={})

        assert file_exists("/missing", context=ctx) is False


class TestGlobFiles:
    """Tests for glob_files function."""

    def test_finds_matching_files(self, mock_context):
        """Returns files matching pattern."""
        ctx = mock_context(
            file_contents={
                "/proc/1/stat": "...",
                "/proc/2/stat": "...",
                "/proc/self/stat": "...",
            }
        )

        files = glob_files("/proc/*/stat", context=ctx)

        assert len(files) == 3

    def test_returns_empty_when_no_matches(self, mock_context):
        """Returns empty list when no files match."""
        ctx = mock_context(file_contents={})

        files = glob_files("/nonexistent/*", context=ctx)

        assert files == []
