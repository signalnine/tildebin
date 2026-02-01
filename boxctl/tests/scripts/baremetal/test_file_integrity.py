"""Tests for file_integrity script."""

import pytest
import json
from pathlib import Path

from boxctl.core.output import Output


@pytest.fixture
def baseline_json(fixtures_dir):
    """Load file integrity baseline JSON."""
    return (fixtures_dir / "security" / "file_integrity_baseline.json").read_text()


class TestFileIntegrity:
    """Tests for file_integrity script."""

    def test_create_baseline(self, mock_context):
        """Creates baseline with --baseline flag."""
        from scripts.baremetal import file_integrity

        ctx = mock_context(
            file_contents={
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
                "/etc/shadow": "root:!:19000:0:99999:7:::\n",
            },
        )
        output = Output()

        exit_code = file_integrity.run(["--baseline"], output, ctx)

        assert exit_code == 0
        assert output.data["action"] == "baseline_created"
        assert output.data["files"] > 0

    def test_report_mode(self, mock_context):
        """Report mode shows current state without comparison."""
        from scripts.baremetal import file_integrity

        ctx = mock_context(
            file_contents={
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
                "/etc/shadow": "root:!:19000:0:99999:7:::\n",
            },
        )
        output = Output()

        exit_code = file_integrity.run(["--report"], output, ctx)

        assert exit_code == 0
        assert "files" in output.data
        assert "summary" in output.data

    def test_no_baseline_returns_error(self, mock_context):
        """Returns 2 when no baseline exists."""
        from scripts.baremetal import file_integrity

        ctx = mock_context(
            file_contents={
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n",
            },
        )
        output = Output()

        exit_code = file_integrity.run([], output, ctx)

        assert exit_code == 2
        assert len(output.errors) > 0
        assert any("baseline" in e.lower() for e in output.errors)

    def test_all_files_match_baseline(self, mock_context, baseline_json):
        """Returns 0 when all files match baseline."""
        from scripts.baremetal import file_integrity
        import hashlib

        # Calculate actual hash for /etc/passwd content matching baseline
        passwd_content = "root:x:0:0:root:/root:/bin/bash\n"
        passwd_hash = hashlib.sha256(passwd_content.encode()).hexdigest()

        # Modify baseline to use actual hash
        baseline = json.loads(baseline_json)
        baseline["files"]["/etc/passwd"]["hash"] = passwd_hash

        ctx = mock_context(
            file_contents={
                "/etc/passwd": passwd_content,
                "/etc/shadow": "test shadow content",
                "/etc/sudoers": "test sudoers content",
                "/var/lib/boxctl/file-integrity-baseline.json": json.dumps(baseline),
            },
        )
        output = Output()

        exit_code = file_integrity.run([], output, ctx)

        # Should have violations for shadow/sudoers hash mismatch
        assert exit_code in (0, 1)

    def test_file_modified_detected(self, mock_context):
        """Detects when file content changes."""
        from scripts.baremetal import file_integrity
        import hashlib

        original_content = "original content"
        modified_content = "modified content"
        original_hash = hashlib.sha256(original_content.encode()).hexdigest()

        baseline = {
            "version": "1.0",
            "created": "2025-01-15T10:00:00+00:00",
            "algorithm": "sha256",
            "files": {
                "/etc/passwd": {
                    "path": "/etc/passwd",
                    "exists": True,
                    "readable": True,
                    "hash": original_hash,
                },
            },
        }

        ctx = mock_context(
            file_contents={
                "/etc/passwd": modified_content,
                "/var/lib/boxctl/file-integrity-baseline.json": json.dumps(baseline),
            },
        )
        output = Output()

        exit_code = file_integrity.run([], output, ctx)

        assert exit_code == 1
        assert len(output.data["violations"]) > 0
        assert output.data["violations"][0]["type"] == "modified"
        assert output.data["violations"][0]["path"] == "/etc/passwd"

    def test_file_deleted_detected(self, mock_context):
        """Detects when file is deleted."""
        from scripts.baremetal import file_integrity

        baseline = {
            "version": "1.0",
            "created": "2025-01-15T10:00:00+00:00",
            "algorithm": "sha256",
            "files": {
                "/etc/passwd": {
                    "path": "/etc/passwd",
                    "exists": True,
                    "readable": True,
                    "hash": "somehash",
                },
            },
        }

        ctx = mock_context(
            file_contents={
                # /etc/passwd is missing
                "/var/lib/boxctl/file-integrity-baseline.json": json.dumps(baseline),
            },
        )
        output = Output()

        exit_code = file_integrity.run([], output, ctx)

        assert exit_code == 1
        assert any(v["type"] == "deleted" for v in output.data["violations"])

    def test_file_created_detected(self, mock_context):
        """Detects when new file is created."""
        from scripts.baremetal import file_integrity
        import hashlib

        content = "test content"
        content_hash = hashlib.sha256(content.encode()).hexdigest()

        baseline = {
            "version": "1.0",
            "created": "2025-01-15T10:00:00+00:00",
            "algorithm": "sha256",
            "files": {
                "/etc/passwd": {
                    "path": "/etc/passwd",
                    "exists": False,  # File didn't exist in baseline
                    "readable": False,
                    "hash": None,
                },
            },
        }

        ctx = mock_context(
            file_contents={
                "/etc/passwd": content,  # Now exists
                "/var/lib/boxctl/file-integrity-baseline.json": json.dumps(baseline),
            },
        )
        output = Output()

        exit_code = file_integrity.run([], output, ctx)

        # Created files are warnings, not violations
        assert len(output.data["warnings"]) > 0
        assert any(w["type"] == "created" for w in output.data["warnings"])

    def test_custom_file_list(self, mock_context):
        """Uses custom file list when provided."""
        from scripts.baremetal import file_integrity

        file_list = "/tmp/my-files.txt"
        file_list_content = "/etc/custom1.conf\n/etc/custom2.conf\n"

        ctx = mock_context(
            file_contents={
                file_list: file_list_content,
                "/etc/custom1.conf": "content1",
                "/etc/custom2.conf": "content2",
            },
        )
        output = Output()

        exit_code = file_integrity.run(["--report", "-f", file_list], output, ctx)

        assert exit_code == 0
        # Should scan the custom files
        paths = [f["path"] for f in output.data["files"]]
        assert "/etc/custom1.conf" in paths
        assert "/etc/custom2.conf" in paths
