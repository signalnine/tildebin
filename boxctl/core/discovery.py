"""Script discovery and filtering."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from boxctl.core.metadata import parse_metadata, MetadataError


@dataclass
class Script:
    """Represents a discovered boxctl script."""

    name: str
    path: Path
    category: str
    tags: list[str]
    brief: str
    requires: list[str] | None = None
    privilege: str | None = None
    related: list[str] | None = None

    @classmethod
    def from_path(cls, path: Path) -> "Script | None":
        """
        Create Script from file path.

        Args:
            path: Path to script file

        Returns:
            Script instance, or None if no valid metadata
        """
        try:
            content = path.read_text()
        except OSError:
            return None

        try:
            metadata = parse_metadata(content)
        except MetadataError:
            return None

        if metadata is None:
            return None

        return cls(
            name=path.name,
            path=path,
            category=metadata["category"],
            tags=metadata["tags"],
            brief=metadata["brief"],
            requires=metadata.get("requires"),
            privilege=metadata.get("privilege"),
            related=metadata.get("related"),
        )

    def matches(
        self,
        category: str | None = None,
        tags: list[str] | None = None,
    ) -> bool:
        """
        Check if script matches filter criteria.

        Args:
            category: Category or category prefix to match
            tags: Tags that must all be present

        Returns:
            True if script matches all criteria
        """
        if category is not None:
            # Match exact category or category prefix
            if not (
                self.category == category or self.category.startswith(category + "/")
            ):
                return False

        if tags is not None:
            # All specified tags must be present
            script_tags = set(self.tags)
            if not all(tag in script_tags for tag in tags):
                return False

        return True


def discover_scripts(directory: Path) -> list[Script]:
    """
    Discover all boxctl scripts in directory.

    Args:
        directory: Root directory to search

    Returns:
        List of discovered Script objects
    """
    scripts = []

    for path in directory.rglob("*.py"):
        if path.is_file():
            script = Script.from_path(path)
            if script is not None:
                scripts.append(script)

    return scripts


def filter_scripts(
    scripts: list[Script],
    category: str | None = None,
    tags: list[str] | None = None,
) -> list[Script]:
    """
    Filter scripts by criteria.

    Args:
        scripts: List of scripts to filter
        category: Category or category prefix to match
        tags: Tags that must all be present

    Returns:
        Filtered list of scripts
    """
    return [s for s in scripts if s.matches(category=category, tags=tags)]
