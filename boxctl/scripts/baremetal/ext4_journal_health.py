#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, filesystem, ext4, journal, storage]
#   requires: [dumpe2fs]
#   privilege: root
#   brief: Monitor ext4 filesystem journal health

"""
Monitor ext4 filesystem journal health and detect potential issues.

Checks for:
- Filesystem error states requiring fsck
- Journal errors recorded in superblock
- Undersized journals causing performance issues
- Missing journal checksum protection
- Mount count approaching fsck threshold

Exit codes:
    0: All ext4 journals healthy
    1: Journal warnings or errors detected
    2: Usage error or missing dependency
"""

import argparse
import json
import re

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_mounts(content: str) -> list[dict]:
    """Parse /proc/mounts for ext4 filesystems."""
    filesystems = []
    for line in content.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            device, mount_point, fs_type, options = parts[0], parts[1], parts[2], parts[3]
            if fs_type == "ext4":
                filesystems.append({
                    "device": device,
                    "mount_point": mount_point,
                    "options": options.split(","),
                })
    return filesystems


def parse_dumpe2fs(output: str) -> dict:
    """Parse dumpe2fs output for journal and filesystem information."""
    info = {
        "journal_uuid": None,
        "journal_device": None,
        "journal_size": None,
        "journal_length": None,
        "filesystem_blocks": None,
        "block_size": None,
        "mount_count": None,
        "max_mount_count": None,
        "filesystem_state": None,
        "errors_count": None,
        "first_error_time": None,
        "last_error_time": None,
        "features": [],
        "journal_features": [],
    }

    for line in output.split("\n"):
        line = line.strip()

        # Journal information
        if line.startswith("Journal UUID:"):
            info["journal_uuid"] = line.split(":", 1)[1].strip()
        elif line.startswith("Journal device:"):
            info["journal_device"] = line.split(":", 1)[1].strip()
        elif line.startswith("Journal size:"):
            size_str = line.split(":", 1)[1].strip()
            match = re.match(r"(\d+)([KMGTP]?)", size_str)
            if match:
                size = int(match.group(1))
                unit = match.group(2)
                multipliers = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
                info["journal_size"] = size * multipliers.get(unit, 1)
        elif line.startswith("Journal length:"):
            try:
                info["journal_length"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass

        # Filesystem information
        elif line.startswith("Block count:"):
            try:
                info["filesystem_blocks"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("Block size:"):
            try:
                info["block_size"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("Mount count:"):
            try:
                info["mount_count"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("Maximum mount count:"):
            try:
                max_count = line.split(":", 1)[1].strip()
                info["max_mount_count"] = int(max_count) if max_count != "-1" else None
            except ValueError:
                pass

        # State and errors
        elif line.startswith("Filesystem state:"):
            info["filesystem_state"] = line.split(":", 1)[1].strip()
        elif line.startswith("FS Error count:"):
            try:
                info["errors_count"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("First error time:"):
            info["first_error_time"] = line.split(":", 1)[1].strip()
        elif line.startswith("Last error time:"):
            info["last_error_time"] = line.split(":", 1)[1].strip()

        # Features
        elif line.startswith("Filesystem features:"):
            features_str = line.split(":", 1)[1].strip()
            info["features"] = features_str.split()
        elif line.startswith("Journal features:"):
            features_str = line.split(":", 1)[1].strip()
            info["journal_features"] = features_str.split()

    # Calculate filesystem size
    if info["filesystem_blocks"] and info["block_size"]:
        info["filesystem_size"] = info["filesystem_blocks"] * info["block_size"]

    return info


def analyze_journal_health(device: str, info: dict) -> tuple[list[dict], list[dict]]:
    """Analyze journal health and return issues found."""
    issues = []
    warnings = []

    # Check filesystem state
    if info.get("filesystem_state"):
        state = info["filesystem_state"].lower()
        if "error" in state:
            issues.append({
                "severity": "CRITICAL",
                "type": "state",
                "message": f"Filesystem in error state: {info['filesystem_state']}",
            })
        elif state != "clean":
            warnings.append({
                "severity": "WARNING",
                "type": "state",
                "message": f"Filesystem state is not clean: {info['filesystem_state']}",
            })

    # Check for recorded errors
    if info.get("errors_count") and info["errors_count"] > 0:
        issues.append({
            "severity": "CRITICAL",
            "type": "errors",
            "message": f"Filesystem has {info['errors_count']} recorded error(s)",
        })
        if info.get("last_error_time"):
            issues.append({
                "severity": "INFO",
                "type": "errors",
                "message": f"Last error occurred: {info['last_error_time']}",
            })

    # Check journal size ratio
    if info.get("journal_size") and info.get("filesystem_size"):
        ratio = info["journal_size"] / info["filesystem_size"]
        if ratio < 0.0001:  # Less than 0.01%
            journal_mb = info["journal_size"] / (1024 * 1024)
            fs_gb = info["filesystem_size"] / (1024**3)
            warnings.append({
                "severity": "WARNING",
                "type": "size",
                "message": f"Journal size may be too small ({journal_mb:.0f}MB for {fs_gb:.1f}GB filesystem)",
            })

    # Check journal features
    if info.get("journal_features"):
        has_checksum = any("checksum" in f.lower() for f in info["journal_features"])
        if not has_checksum:
            warnings.append({
                "severity": "INFO",
                "type": "features",
                "message": "Journal checksums not enabled (recommended for data integrity)",
            })

    # Check filesystem features
    if info.get("features"):
        if "has_journal" not in info["features"]:
            issues.append({
                "severity": "CRITICAL",
                "type": "features",
                "message": "Filesystem does not have journaling enabled",
            })

    # Check mount count vs max mount count
    if info.get("mount_count") and info.get("max_mount_count"):
        if info["mount_count"] >= info["max_mount_count"]:
            warnings.append({
                "severity": "WARNING",
                "type": "fsck",
                "message": f"Filesystem has reached max mount count ({info['mount_count']}/{info['max_mount_count']}), fsck recommended",
            })

    return issues, warnings


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description="Monitor ext4 journal health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    parser.add_argument("-d", "--device", help="Check specific device")
    opts = parser.parse_args(args)

    # Check for dumpe2fs
    if not context.check_tool("dumpe2fs"):
        output.error("dumpe2fs not found. Install e2fsprogs package.")
        return 2

    # Get filesystems to check
    if opts.device:
        filesystems = [{"device": opts.device, "mount_point": "specified", "options": []}]
    else:
        try:
            mounts_content = context.read_file("/proc/mounts")
        except (FileNotFoundError, IOError) as e:
            output.error(f"Unable to read /proc/mounts: {e}")
            return 2

        filesystems = parse_mounts(mounts_content)

        if not filesystems:
            output.emit({"filesystems": [], "summary": {"total": 0}})
            if opts.format != "json" and not opts.warn_only:
                print("No ext4 filesystems found")
            return 0

    # Check each filesystem
    results = []
    for fs in filesystems:
        result = {
            "device": fs["device"],
            "mount_point": fs["mount_point"],
            "status": "unknown",
            "issues": [],
            "warnings": [],
            "info": {},
        }

        # Run dumpe2fs
        try:
            dump_result = context.run(["dumpe2fs", "-h", fs["device"]], check=False)
            if dump_result.returncode != 0:
                if "Permission denied" in dump_result.stderr or "Operation not permitted" in dump_result.stderr:
                    result["status"] = "permission_denied"
                    result["issues"].append({
                        "severity": "ERROR",
                        "type": "access",
                        "message": f"Permission denied reading {fs['device']} (run as root)",
                    })
                else:
                    result["status"] = "error"
                    result["issues"].append({
                        "severity": "ERROR",
                        "type": "access",
                        "message": f"Failed to read filesystem info: {dump_result.stderr.strip()}",
                    })
                results.append(result)
                continue

            info = parse_dumpe2fs(dump_result.stdout)
            result["info"] = info
        except Exception as e:
            result["status"] = "error"
            result["issues"].append({
                "severity": "ERROR",
                "type": "access",
                "message": str(e),
            })
            results.append(result)
            continue

        # Analyze journal health
        issues, warnings = analyze_journal_health(fs["device"], info)
        result["issues"].extend(issues)
        result["warnings"].extend(warnings)

        # Determine status
        all_items = result["issues"] + result["warnings"]
        if any(i["severity"] == "CRITICAL" for i in all_items):
            result["status"] = "critical"
        elif any(i["severity"] in ["ERROR", "WARNING"] for i in all_items):
            result["status"] = "warning"
        elif all_items:
            result["status"] = "info"
        else:
            result["status"] = "healthy"

        results.append(result)

    # Output
    has_issues = any(r["status"] in ["critical", "warning", "error"] for r in results)

    if opts.format == "json":
        # Clean up info for JSON (remove None values)
        for r in results:
            if "info" in r:
                r["info"] = {k: v for k, v in r["info"].items() if v is not None}

        json_output = {
            "filesystems": results,
            "summary": {
                "total": len(results),
                "healthy": sum(1 for r in results if r["status"] == "healthy"),
                "warning": sum(1 for r in results if r["status"] in ["warning", "info"]),
                "critical": sum(1 for r in results if r["status"] == "critical"),
                "error": sum(1 for r in results if r["status"] in ["error", "permission_denied"]),
            },
        }
        if not opts.warn_only or has_issues:
            print(json.dumps(json_output, indent=2))
    else:
        if not opts.warn_only or has_issues:
            lines = []
            lines.append("Ext4 Journal Health Monitor")
            lines.append("=" * 40)

            for result in results:
                if opts.warn_only and result["status"] == "healthy":
                    continue

                status_icon = {
                    "healthy": "[OK]",
                    "info": "[INFO]",
                    "warning": "[WARN]",
                    "critical": "[CRIT]",
                    "error": "[ERR]",
                    "permission_denied": "[PERM]",
                }.get(result["status"], "[??]")

                lines.append(f"{status_icon} {result['device']} ({result['mount_point']})")

                if opts.verbose or result["status"] != "healthy":
                    info = result.get("info", {})

                    if info.get("filesystem_state"):
                        lines.append(f"    State: {info['filesystem_state']}")

                    if info.get("journal_size"):
                        journal_mb = info["journal_size"] / (1024 * 1024)
                        lines.append(f"    Journal size: {journal_mb:.1f}MB")

                    if info.get("errors_count"):
                        lines.append(f"    Error count: {info['errors_count']}")

                    if info.get("mount_count") and info.get("max_mount_count"):
                        lines.append(f"    Mount count: {info['mount_count']}/{info['max_mount_count']}")

                for issue in result.get("issues", []):
                    if opts.warn_only and issue["severity"] == "INFO":
                        continue
                    lines.append(f"    [{issue['severity']}] {issue['message']}")

                for warning in result.get("warnings", []):
                    if opts.warn_only and warning["severity"] == "INFO":
                        continue
                    lines.append(f"    [{warning['severity']}] {warning['message']}")

            if not has_issues and not opts.warn_only:
                lines.append("")
                lines.append(f"[OK] All {len(results)} ext4 journal(s) healthy")

            print("\n".join(lines))

    output.emit({
        "filesystems": results,
        "total": len(results),
        "healthy": sum(1 for r in results if r["status"] == "healthy"),
    })
    output.set_summary(f"{len(results)} filesystems, {sum(1 for r in results if r['status'] != 'healthy')} issues")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
