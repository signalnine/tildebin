"""Script metadata parsing from header comments."""

import re
from typing import Any

import yaml


class MetadataError(Exception):
    """Error parsing or validating script metadata."""

    pass


# Required fields in metadata
REQUIRED_FIELDS = {"category", "tags", "brief"}

# Valid privilege levels
VALID_PRIVILEGES = {"root", "user", None}

# Category pattern: parent/child
CATEGORY_PATTERN = re.compile(r"^[a-z]+/[a-z]+$")

# Maximum lines to search for header
MAX_HEADER_LINES = 20


def parse_metadata(content: str) -> dict[str, Any] | None:
    """
    Parse boxctl metadata from script header comments.

    Args:
        content: Full script content

    Returns:
        Parsed metadata dict, or None if no header found

    Raises:
        MetadataError: If header found but malformed or missing required fields
    """
    lines = content.split("\n")
    header_lines = lines[:MAX_HEADER_LINES]

    # Find the start of boxctl metadata block
    start_idx = None
    for i, line in enumerate(header_lines):
        if line.strip() == "# boxctl:":
            start_idx = i
            break

    if start_idx is None:
        return None

    # Collect all indented comment lines after "# boxctl:"
    yaml_lines = []
    for line in header_lines[start_idx + 1 :]:
        # Check if line is a comment with indentation (metadata continuation)
        if line.startswith("#   "):
            # Remove comment prefix and one level of indentation
            yaml_content = line[4:]  # Remove "# " + 2 spaces
            yaml_lines.append(yaml_content)
        elif line.startswith("#") and line.strip() == "#":
            # Empty comment line, end of block
            break
        elif not line.startswith("#"):
            # Non-comment line, end of block
            break
        else:
            # Comment but not indented properly, end of block
            break

    if not yaml_lines:
        return None

    # Parse YAML
    yaml_content = "\n".join(yaml_lines)
    try:
        metadata = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        raise MetadataError(f"Invalid YAML in metadata: {e}")

    if not isinstance(metadata, dict):
        raise MetadataError("Metadata must be a YAML mapping")

    # Check required fields
    missing = REQUIRED_FIELDS - set(metadata.keys())
    if missing:
        raise MetadataError(f"Missing required fields: {', '.join(sorted(missing))}")

    return metadata


def validate_metadata(metadata: dict[str, Any]) -> list[str]:
    """
    Validate metadata and return warnings.

    Args:
        metadata: Parsed metadata dict

    Returns:
        List of warning messages (empty if valid)
    """
    warnings = []

    # Validate category format
    category = metadata.get("category", "")
    if not CATEGORY_PATTERN.match(category):
        warnings.append(f"Category '{category}' should be in format 'parent/child'")

    # Validate privilege value
    privilege = metadata.get("privilege")
    if privilege is not None and privilege not in VALID_PRIVILEGES:
        warnings.append(
            f"Privilege '{privilege}' is not valid. Use 'root' or 'user'."
        )

    # Validate tags is non-empty
    tags = metadata.get("tags", [])
    if not tags:
        warnings.append("Tags list should not be empty")

    return warnings
