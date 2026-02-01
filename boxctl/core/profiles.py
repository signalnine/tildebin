"""Profile loading and validation."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ProfileError(Exception):
    """Error loading or validating a profile."""

    pass


@dataclass
class Profile:
    """A boxctl profile for grouping scripts."""

    name: str
    description: str
    scripts: list[str]
    options: dict[str, Any] = field(default_factory=dict)
    path: Path | None = None


def load_profile(path: Path) -> Profile:
    """
    Load a profile from a YAML file.

    Args:
        path: Path to the profile YAML file

    Returns:
        Loaded Profile object

    Raises:
        ProfileError: If file not found or invalid
    """
    if not path.exists():
        raise ProfileError(f"Profile not found: {path}")

    try:
        content = path.read_text()
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise ProfileError(f"Invalid YAML in profile {path}: {e}")

    if not isinstance(data, dict):
        raise ProfileError(f"Profile must be a YAML mapping: {path}")

    # Validate required fields
    if "name" not in data:
        raise ProfileError(f"Profile missing required field 'name': {path}")
    if "scripts" not in data:
        raise ProfileError(f"Profile missing required field 'scripts': {path}")

    return Profile(
        name=data["name"],
        description=data.get("description", ""),
        scripts=data.get("scripts", []),
        options=data.get("options", {}),
        path=path,
    )


def validate_profile(profile: Profile) -> list[str]:
    """
    Validate a profile and return warnings.

    Args:
        profile: Profile to validate

    Returns:
        List of warning messages (empty if valid)
    """
    warnings = []

    if not profile.scripts:
        warnings.append(f"Profile '{profile.name}' has empty scripts list")

    return warnings


def find_profiles(directory: Path) -> list[Profile]:
    """
    Find all profiles in a directory.

    Args:
        directory: Directory to search

    Returns:
        List of loaded Profile objects
    """
    profiles = []

    if not directory.exists():
        return profiles

    for path in directory.glob("*.yaml"):
        try:
            profile = load_profile(path)
            profiles.append(profile)
        except ProfileError:
            # Skip invalid profiles
            continue

    # Also check .yml extension
    for path in directory.glob("*.yml"):
        try:
            profile = load_profile(path)
            profiles.append(profile)
        except ProfileError:
            continue

    return profiles
