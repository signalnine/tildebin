"""Tests for script metadata parsing."""

import pytest
from boxctl.core.metadata import parse_metadata, MetadataError, validate_metadata


VALID_HEADER = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage]
#   requires: [smartctl]
#   privilege: root
#   brief: Check disk health using SMART attributes
'''

MINIMAL_HEADER = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   brief: Minimal script
'''

NO_HEADER = '''#!/usr/bin/env python3
"""A script without boxctl metadata."""

def main():
    pass
'''

INVALID_YAML = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [unclosed
'''


class TestParseMetadata:
    """Tests for parse_metadata function."""

    def test_parses_valid_header(self):
        """Parses all fields from valid header."""
        meta = parse_metadata(VALID_HEADER)
        assert meta["category"] == "baremetal/disk"
        assert meta["tags"] == ["health", "smart", "storage"]
        assert meta["requires"] == ["smartctl"]
        assert meta["privilege"] == "root"
        assert meta["brief"] == "Check disk health using SMART attributes"

    def test_parses_minimal_header(self):
        """Parses minimal required fields."""
        meta = parse_metadata(MINIMAL_HEADER)
        assert meta["category"] == "baremetal/disk"
        assert meta["tags"] == ["health"]
        assert meta["brief"] == "Minimal script"
        assert meta.get("requires") is None
        assert meta.get("privilege") is None

    def test_returns_none_for_no_header(self):
        """Returns None for scripts without boxctl header."""
        meta = parse_metadata(NO_HEADER)
        assert meta is None

    def test_raises_on_invalid_yaml(self):
        """Raises MetadataError for malformed YAML."""
        with pytest.raises(MetadataError):
            parse_metadata(INVALID_YAML)

    def test_validates_required_fields(self):
        """Raises MetadataError when required fields missing."""
        missing_category = '''#!/usr/bin/env python3
# boxctl:
#   tags: [test]
#   brief: Missing category
'''
        with pytest.raises(MetadataError, match="category"):
            parse_metadata(missing_category)

    def test_header_within_first_20_lines(self):
        """Finds header only within first 20 lines."""
        late_header = "\n" * 25 + VALID_HEADER
        meta = parse_metadata(late_header)
        assert meta is None

    def test_parses_related_field(self):
        """Parses optional related field."""
        header_with_related = '''#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health]
#   brief: Test script
#   related: [other_script, another_script]
'''
        meta = parse_metadata(header_with_related)
        assert meta["related"] == ["other_script", "another_script"]


class TestValidateMetadata:
    """Tests for validate_metadata function."""

    def test_valid_metadata_no_warnings(self):
        """Valid metadata returns no warnings."""
        meta = {
            "category": "baremetal/disk",
            "tags": ["health"],
            "brief": "Test script",
        }
        warnings = validate_metadata(meta)
        assert len(warnings) == 0

    def test_invalid_category_format(self):
        """Invalid category format returns warning."""
        meta = {
            "category": "invalid",
            "tags": ["health"],
            "brief": "Test script",
        }
        warnings = validate_metadata(meta)
        assert any("category" in w.lower() for w in warnings)

    def test_invalid_privilege_value(self):
        """Invalid privilege value returns warning."""
        meta = {
            "category": "baremetal/disk",
            "tags": ["health"],
            "brief": "Test script",
            "privilege": "admin",  # Invalid
        }
        warnings = validate_metadata(meta)
        assert any("privilege" in w.lower() for w in warnings)

    def test_empty_tags_warning(self):
        """Empty tags list returns warning."""
        meta = {
            "category": "baremetal/disk",
            "tags": [],
            "brief": "Test script",
        }
        warnings = validate_metadata(meta)
        assert any("tags" in w.lower() for w in warnings)
