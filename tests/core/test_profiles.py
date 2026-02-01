"""Tests for profile loader."""

import pytest
from pathlib import Path

from boxctl.core.profiles import (
    load_profile,
    validate_profile,
    ProfileError,
    find_profiles,
    Profile,
)


VALID_PROFILE = """
name: disk-health
description: Check all disk-related health metrics
scripts:
  - disk_health
  - disk_space_forecaster
  - disk_io_latency_monitor
"""

PROFILE_WITH_OPTIONS = """
name: full-health-check
description: Complete system health check
scripts:
  - disk_health
  - memory_usage
  - cpu_load
options:
  timeout: 120
  parallel: true
"""

INVALID_PROFILE_NO_NAME = """
description: Missing name
scripts:
  - disk_health
"""

INVALID_PROFILE_NO_SCRIPTS = """
name: empty
description: Has no scripts
"""


class TestLoadProfile:
    """Tests for load_profile function."""

    def test_loads_valid_profile(self, tmp_path):
        """Loads profile from YAML file."""
        profile_file = tmp_path / "disk-health.yaml"
        profile_file.write_text(VALID_PROFILE)

        profile = load_profile(profile_file)

        assert profile.name == "disk-health"
        assert profile.description == "Check all disk-related health metrics"
        assert len(profile.scripts) == 3
        assert "disk_health" in profile.scripts

    def test_loads_profile_with_options(self, tmp_path):
        """Loads profile options."""
        profile_file = tmp_path / "full.yaml"
        profile_file.write_text(PROFILE_WITH_OPTIONS)

        profile = load_profile(profile_file)

        assert profile.options["timeout"] == 120
        assert profile.options["parallel"] is True

    def test_raises_on_missing_file(self, tmp_path):
        """Raises ProfileError for missing file."""
        with pytest.raises(ProfileError, match="not found"):
            load_profile(tmp_path / "missing.yaml")

    def test_raises_on_invalid_yaml(self, tmp_path):
        """Raises ProfileError for invalid YAML."""
        profile_file = tmp_path / "bad.yaml"
        profile_file.write_text("name: [unclosed")

        with pytest.raises(ProfileError, match="Invalid YAML"):
            load_profile(profile_file)


class TestValidateProfile:
    """Tests for validate_profile function."""

    def test_valid_profile_no_errors(self, tmp_path):
        """Valid profile returns no errors."""
        profile_file = tmp_path / "valid.yaml"
        profile_file.write_text(VALID_PROFILE)
        profile = load_profile(profile_file)

        errors = validate_profile(profile)

        assert len(errors) == 0

    def test_missing_name_error(self, tmp_path):
        """Missing name returns error."""
        profile_file = tmp_path / "noname.yaml"
        profile_file.write_text(INVALID_PROFILE_NO_NAME)

        with pytest.raises(ProfileError, match="name"):
            load_profile(profile_file)

    def test_missing_scripts_error(self, tmp_path):
        """Missing scripts returns error."""
        profile_file = tmp_path / "noscripts.yaml"
        profile_file.write_text(INVALID_PROFILE_NO_SCRIPTS)

        with pytest.raises(ProfileError, match="scripts"):
            load_profile(profile_file)

    def test_empty_scripts_warning(self, tmp_path):
        """Empty scripts list returns warning."""
        profile_yaml = """
name: empty-scripts
description: Has empty scripts
scripts: []
"""
        profile_file = tmp_path / "empty.yaml"
        profile_file.write_text(profile_yaml)
        profile = load_profile(profile_file)

        errors = validate_profile(profile)

        assert any("empty" in e.lower() for e in errors)


class TestFindProfiles:
    """Tests for find_profiles function."""

    def test_finds_profiles_in_directory(self, tmp_path):
        """Finds all .yaml profiles in directory."""
        (tmp_path / "profile1.yaml").write_text(VALID_PROFILE)
        (tmp_path / "profile2.yaml").write_text(PROFILE_WITH_OPTIONS)
        (tmp_path / "readme.md").write_text("# Not a profile")

        profiles = find_profiles(tmp_path)

        assert len(profiles) == 2

    def test_returns_empty_for_no_profiles(self, tmp_path):
        """Returns empty list when no profiles found."""
        profiles = find_profiles(tmp_path)
        assert profiles == []

    def test_skips_invalid_profiles(self, tmp_path):
        """Skips profiles that fail to load."""
        (tmp_path / "valid.yaml").write_text(VALID_PROFILE)
        (tmp_path / "invalid.yaml").write_text("name: [broken")

        profiles = find_profiles(tmp_path)

        assert len(profiles) == 1
        assert profiles[0].name == "disk-health"


class TestProfile:
    """Tests for Profile dataclass."""

    def test_profile_attributes(self, tmp_path):
        """Profile has expected attributes."""
        profile_file = tmp_path / "test.yaml"
        profile_file.write_text(VALID_PROFILE)

        profile = load_profile(profile_file)

        assert hasattr(profile, "name")
        assert hasattr(profile, "description")
        assert hasattr(profile, "scripts")
        assert hasattr(profile, "options")
        assert hasattr(profile, "path")

    def test_profile_path_stored(self, tmp_path):
        """Profile stores its source path."""
        profile_file = tmp_path / "test.yaml"
        profile_file.write_text(VALID_PROFILE)

        profile = load_profile(profile_file)

        assert profile.path == profile_file
