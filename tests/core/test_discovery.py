"""Tests for script discovery."""

import pytest
from pathlib import Path

from boxctl.core.discovery import discover_scripts, Script, filter_scripts


SAMPLE_SCRIPT = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart]
#   requires: [smartctl]
#   privilege: root
#   brief: Check disk health

def main():
    pass
'''

SAMPLE_SCRIPT_2 = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/memory
#   tags: [health, performance]
#   brief: Check memory usage

def main():
    pass
'''

NO_METADATA_SCRIPT = '''#!/usr/bin/env python3
"""A script without boxctl metadata."""

def main():
    pass
'''


class TestScript:
    """Tests for Script dataclass."""

    def test_script_from_path(self, tmp_path):
        """Script.from_path loads metadata from file."""
        script_file = tmp_path / "test_script.py"
        script_file.write_text(SAMPLE_SCRIPT)

        script = Script.from_path(script_file)

        assert script.name == "test_script.py"
        assert script.path == script_file
        assert script.category == "baremetal/disk"
        assert script.tags == ["health", "smart"]
        assert script.requires == ["smartctl"]
        assert script.privilege == "root"
        assert script.brief == "Check disk health"

    def test_script_from_path_no_metadata(self, tmp_path):
        """Script.from_path returns None for scripts without metadata."""
        script_file = tmp_path / "no_meta.py"
        script_file.write_text(NO_METADATA_SCRIPT)

        script = Script.from_path(script_file)

        assert script is None

    def test_script_matches_category(self, tmp_path):
        """Script.matches filters by category."""
        script_file = tmp_path / "test.py"
        script_file.write_text(SAMPLE_SCRIPT)
        script = Script.from_path(script_file)

        assert script.matches(category="baremetal/disk")
        assert script.matches(category="baremetal")
        assert not script.matches(category="k8s")

    def test_script_matches_tags(self, tmp_path):
        """Script.matches filters by tags."""
        script_file = tmp_path / "test.py"
        script_file.write_text(SAMPLE_SCRIPT)
        script = Script.from_path(script_file)

        assert script.matches(tags=["health"])
        assert script.matches(tags=["smart"])
        assert script.matches(tags=["health", "smart"])
        assert not script.matches(tags=["network"])


class TestDiscoverScripts:
    """Tests for discover_scripts function."""

    def test_discovers_scripts_in_directory(self, tmp_path):
        """Discovers all scripts with metadata in directory."""
        (tmp_path / "script1.py").write_text(SAMPLE_SCRIPT)
        (tmp_path / "script2.py").write_text(SAMPLE_SCRIPT_2)
        (tmp_path / "no_meta.py").write_text(NO_METADATA_SCRIPT)

        scripts = discover_scripts(tmp_path)

        assert len(scripts) == 2
        names = {s.name for s in scripts}
        assert "script1.py" in names
        assert "script2.py" in names
        assert "no_meta.py" not in names

    def test_discovers_scripts_recursive(self, tmp_path):
        """Discovers scripts in subdirectories."""
        subdir = tmp_path / "baremetal"
        subdir.mkdir()
        (subdir / "disk_check.py").write_text(SAMPLE_SCRIPT)
        (tmp_path / "root_script.py").write_text(SAMPLE_SCRIPT_2)

        scripts = discover_scripts(tmp_path)

        assert len(scripts) == 2
        paths = {s.path for s in scripts}
        assert subdir / "disk_check.py" in paths
        assert tmp_path / "root_script.py" in paths

    def test_discovers_only_python_files(self, tmp_path):
        """Only discovers .py files."""
        (tmp_path / "script.py").write_text(SAMPLE_SCRIPT)
        (tmp_path / "script.sh").write_text("#!/bin/bash\necho hello")
        (tmp_path / "README.md").write_text("# Readme")

        scripts = discover_scripts(tmp_path)

        assert len(scripts) == 1
        assert scripts[0].name == "script.py"

    def test_empty_directory(self, tmp_path):
        """Returns empty list for empty directory."""
        scripts = discover_scripts(tmp_path)
        assert scripts == []


class TestFilterScripts:
    """Tests for filter_scripts function."""

    def test_filter_by_category(self, tmp_path):
        """Filters scripts by category."""
        (tmp_path / "disk.py").write_text(SAMPLE_SCRIPT)
        (tmp_path / "memory.py").write_text(SAMPLE_SCRIPT_2)

        scripts = discover_scripts(tmp_path)
        filtered = filter_scripts(scripts, category="baremetal/disk")

        assert len(filtered) == 1
        assert filtered[0].name == "disk.py"

    def test_filter_by_category_prefix(self, tmp_path):
        """Filters scripts by category prefix."""
        (tmp_path / "disk.py").write_text(SAMPLE_SCRIPT)
        (tmp_path / "memory.py").write_text(SAMPLE_SCRIPT_2)

        scripts = discover_scripts(tmp_path)
        filtered = filter_scripts(scripts, category="baremetal")

        assert len(filtered) == 2

    def test_filter_by_tags(self, tmp_path):
        """Filters scripts by tags."""
        (tmp_path / "disk.py").write_text(SAMPLE_SCRIPT)
        (tmp_path / "memory.py").write_text(SAMPLE_SCRIPT_2)

        scripts = discover_scripts(tmp_path)
        filtered = filter_scripts(scripts, tags=["smart"])

        assert len(filtered) == 1
        assert filtered[0].name == "disk.py"

    def test_filter_by_multiple_tags(self, tmp_path):
        """Scripts must match all specified tags."""
        (tmp_path / "disk.py").write_text(SAMPLE_SCRIPT)
        (tmp_path / "memory.py").write_text(SAMPLE_SCRIPT_2)

        scripts = discover_scripts(tmp_path)
        # Both have "health" tag
        filtered = filter_scripts(scripts, tags=["health"])
        assert len(filtered) == 2

        # Only disk has "smart" tag
        filtered = filter_scripts(scripts, tags=["health", "smart"])
        assert len(filtered) == 1

    def test_filter_combined(self, tmp_path):
        """Combines category and tag filters."""
        (tmp_path / "disk.py").write_text(SAMPLE_SCRIPT)
        (tmp_path / "memory.py").write_text(SAMPLE_SCRIPT_2)

        scripts = discover_scripts(tmp_path)
        filtered = filter_scripts(
            scripts,
            category="baremetal/memory",
            tags=["health"],
        )

        assert len(filtered) == 1
        assert filtered[0].name == "memory.py"

    def test_filter_no_matches(self, tmp_path):
        """Returns empty list when no scripts match."""
        (tmp_path / "disk.py").write_text(SAMPLE_SCRIPT)

        scripts = discover_scripts(tmp_path)
        filtered = filter_scripts(scripts, category="k8s")

        assert filtered == []
