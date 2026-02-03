#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [integrity, security, compliance, checksums, fim]
#   requires: []
#   privilege: root
#   related: [ssl_cert_scanner, security_policy]
#   brief: Monitor critical system files for integrity violations

"""
Monitor critical system files for unexpected changes (file integrity monitoring).

Computes and verifies checksums of critical system files to detect unauthorized
modifications. This is essential for:
- Security compliance (PCI-DSS, HIPAA, SOC2)
- Detecting rootkits and malware
- Configuration drift detection

Returns:
    0 - All files match baseline / baseline created
    1 - File integrity violations detected
    2 - Error
"""

import argparse
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# Default critical files to monitor
DEFAULT_CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/fstab",
    "/etc/hosts",
    "/etc/crontab",
]


def compute_file_hash(context: Context, filepath: str, algorithm: str = "sha256") -> str | None:
    """Compute cryptographic hash of a file."""
    try:
        content = context.read_file(filepath)
        hasher = hashlib.new(algorithm)
        hasher.update(content.encode("utf-8", errors="surrogateescape"))
        return hasher.hexdigest()
    except (IOError, OSError, FileNotFoundError):
        return None


def get_file_info(context: Context, filepath: str, algorithm: str = "sha256") -> dict[str, Any]:
    """Get complete file information including hash and metadata."""
    exists = context.file_exists(filepath)

    info: dict[str, Any] = {
        "path": filepath,
        "exists": exists,
        "readable": False,
        "hash": None,
        "size": None,
        "mode": None,
    }

    if exists:
        try:
            content = context.read_file(filepath)
            info["readable"] = True
            hasher = hashlib.new(algorithm)
            hasher.update(content.encode("utf-8", errors="surrogateescape"))
            info["hash"] = hasher.hexdigest()
            info["size"] = len(content)
        except (IOError, OSError, PermissionError):
            info["readable"] = False

    return info


def create_baseline(context: Context, files: list[str], algorithm: str = "sha256") -> dict[str, Any]:
    """Create a baseline of file states."""
    baseline: dict[str, Any] = {
        "version": "1.0",
        "created": datetime.now(timezone.utc).isoformat(),
        "algorithm": algorithm,
        "files": {},
    }

    for filepath in files:
        info = get_file_info(context, filepath, algorithm)
        baseline["files"][filepath] = info

    return baseline


def verify_against_baseline(
    current: dict[str, Any], baseline: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Compare current state against baseline and return violations."""
    violations = []
    warnings = []

    baseline_files = baseline.get("files", {})

    for filepath, baseline_info in baseline_files.items():
        current_info = current["files"].get(filepath)

        if not current_info:
            violations.append({
                "type": "missing_check",
                "path": filepath,
                "message": "File not checked in current scan",
                "severity": "warning",
            })
            continue

        # File existence change
        if baseline_info.get("exists") and not current_info.get("exists"):
            violations.append({
                "type": "deleted",
                "path": filepath,
                "message": "File was deleted",
                "severity": "critical",
            })
            continue

        if not baseline_info.get("exists") and current_info.get("exists"):
            warnings.append({
                "type": "created",
                "path": filepath,
                "message": "File was created (did not exist in baseline)",
                "severity": "warning",
            })
            continue

        if not current_info.get("exists"):
            continue

        # Hash change (most critical)
        baseline_hash = baseline_info.get("hash")
        current_hash = current_info.get("hash")

        if baseline_hash and current_hash and baseline_hash != current_hash:
            violations.append({
                "type": "modified",
                "path": filepath,
                "message": "File content changed",
                "severity": "critical",
                "baseline_hash": baseline_hash[:16] + "...",
                "current_hash": current_hash[:16] + "...",
            })

    # Check for new files
    for filepath, current_info in current["files"].items():
        if filepath not in baseline_files and current_info.get("exists"):
            warnings.append({
                "type": "new_file",
                "path": filepath,
                "message": "New file not in baseline",
                "severity": "info",
            })

    return violations, warnings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor file integrity")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-b", "--baseline", action="store_true", help="Create new baseline")
    parser.add_argument("--baseline-file", help="Path to baseline file")
    parser.add_argument("-r", "--report", action="store_true", help="Report current state only")
    parser.add_argument("-f", "--files", help="File containing list of files to monitor")
    parser.add_argument("--algorithm", "-a", choices=["sha256", "sha512", "sha1", "md5"], default="sha256")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show warnings")
    opts = parser.parse_args(args)

    # Determine baseline path
    baseline_path = opts.baseline_file or "/var/lib/boxctl/file-integrity-baseline.json"

    # Build file list
    if opts.files:
        try:
            content = context.read_file(opts.files)
            file_list = [line.strip() for line in content.split("\n") if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            output.error(f"File list not found: {opts.files}")
            return 2
    else:
        file_list = DEFAULT_CRITICAL_FILES

    # Create current state
    current = create_baseline(context, file_list, opts.algorithm)

    # Mode: Create baseline
    if opts.baseline:
        file_count = len(current["files"])
        accessible = sum(1 for f in current["files"].values() if f.get("readable"))

        output.emit({
            "action": "baseline_created",
            "path": baseline_path,
            "files": file_count,
            "accessible": accessible,
            "timestamp": current["created"],
        })
        output.set_summary(f"Baseline created: {accessible}/{file_count} files")

        output.render(opts.format, "Monitor critical system files for integrity violations")
        return 0

    # Mode: Report only
    if opts.report:
        output.emit({
            "files": list(current["files"].values()),
            "summary": {
                "total": len(current["files"]),
                "accessible": sum(1 for f in current["files"].values() if f.get("readable")),
            },
        })
        output.set_summary(f"Scanned {len(current['files'])} files")

        output.render(opts.format, "Monitor critical system files for integrity violations")
        return 0

    # Mode: Verify against baseline
    try:
        baseline_content = context.read_file(baseline_path)
        baseline = json.loads(baseline_content)
    except FileNotFoundError:
        output.error(f"No baseline found at {baseline_path}")
        output.error("Create one with: --baseline")

        output.render(opts.format, "Monitor critical system files for integrity violations")
        return 2
    except json.JSONDecodeError as e:
        output.error(f"Invalid baseline file: {e}")

        output.render(opts.format, "Monitor critical system files for integrity violations")
        return 2

    # Verify
    violations, warnings = verify_against_baseline(current, baseline)

    # Build output
    output.emit({
        "violations": violations,
        "warnings": warnings,
        "summary": {
            "total_files": len(current["files"]),
            "violations": len(violations),
            "warnings": len(warnings),
            "critical_violations": sum(1 for v in violations if v.get("severity") == "critical"),
        },
        "healthy": len(violations) == 0,
    })

    critical_count = sum(1 for v in violations if v.get("severity") == "critical")
    output.set_summary(f"{len(violations)} violations, {len(warnings)} warnings")


    output.render(opts.format, "Monitor critical system files for integrity violations")
    return 1 if violations else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
