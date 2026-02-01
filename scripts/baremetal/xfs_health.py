#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, filesystem, xfs, storage]
#   requires: [xfs_info]
#   brief: Monitor XFS filesystem health

"""
Monitor XFS filesystem health and detect potential issues.

Checks for:
- Disk space usage approaching critical levels
- Dangerous mount options (nobarrier)
- Log device sizing issues
- Allocation group configuration issues

Exit codes:
    0: All XFS filesystems healthy
    1: Warnings or errors detected
    2: Usage error or missing dependency
"""

import argparse
import json
import re

from boxctl.core.context import Context
from boxctl.core.output import Output


DANGEROUS_OPTIONS = {
    "nobarrier": "Data integrity risk on power failure",
    "barrier=0": "Data integrity risk on power failure",
}


def parse_mounts(content: str) -> list[dict]:
    """Parse /proc/mounts for XFS filesystems."""
    filesystems = []
    for line in content.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            device, mount_point, fs_type, options = parts[0], parts[1], parts[2], parts[3]
            if fs_type == "xfs":
                filesystems.append({
                    "device": device,
                    "mount_point": mount_point,
                    "options": options.split(","),
                })
    return filesystems


def parse_xfs_info(output: str) -> dict:
    """Parse xfs_info output for filesystem information."""
    info = {
        "meta_data": {},
        "data": {},
        "naming": {},
        "log": {},
        "realtime": {},
    }

    current_section = None

    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Detect section
        if line.startswith("meta-data="):
            current_section = "meta_data"
        elif line.startswith("data"):
            current_section = "data"
        elif line.startswith("naming"):
            current_section = "naming"
        elif line.startswith("log"):
            current_section = "log"
        elif line.startswith("realtime"):
            current_section = "realtime"

        # Parse key=value pairs
        pairs = re.findall(r"(\w+)=([^\s,]+)", line)
        for key, value in pairs:
            if current_section:
                if value.isdigit():
                    value = int(value)
                info[current_section][key] = value

        # Parse bsize
        bsize_match = re.search(r"bsize=(\d+)", line)
        if bsize_match and current_section:
            info[current_section]["bsize"] = int(bsize_match.group(1))

        # Parse blocks
        blocks_match = re.search(r"blocks=(\d+)", line)
        if blocks_match and current_section:
            info[current_section]["blocks"] = int(blocks_match.group(1))

        # Parse sectsz
        sectsz_match = re.search(r"sectsz=(\d+)", line)
        if sectsz_match and current_section:
            info[current_section]["sectsz"] = int(sectsz_match.group(1))

    return info


def parse_df_output(output: str) -> dict:
    """Parse df -B1 output."""
    info = {
        "size_bytes": 0,
        "used_bytes": 0,
        "available_bytes": 0,
        "use_percent": 0,
    }

    lines = output.strip().split("\n")
    if len(lines) >= 2:
        parts = lines[1].split()
        if len(parts) >= 5:
            try:
                info["size_bytes"] = int(parts[1])
                info["used_bytes"] = int(parts[2])
                info["available_bytes"] = int(parts[3])
                use_str = parts[4].rstrip("%")
                info["use_percent"] = int(use_str) if use_str.isdigit() else 0
            except (ValueError, IndexError):
                pass

    return info


def check_mount_options(options: list[str]) -> list[dict]:
    """Check mount options for issues."""
    issues = []

    for opt in options:
        if opt in DANGEROUS_OPTIONS:
            issues.append({
                "severity": "WARNING",
                "type": "mount_option",
                "message": f"Option '{opt}': {DANGEROUS_OPTIONS[opt]}",
            })

    return issues


def analyze_xfs_health(mount_point: str, xfs_info: dict, df_info: dict, options: list[str]) -> tuple[list[dict], list[dict]]:
    """Analyze XFS filesystem health."""
    issues = []
    warnings = []

    # Check disk usage
    if df_info.get("use_percent", 0) >= 95:
        issues.append({
            "severity": "CRITICAL",
            "type": "space",
            "message": f"Filesystem is {df_info['use_percent']}% full",
        })
    elif df_info.get("use_percent", 0) >= 85:
        warnings.append({
            "severity": "WARNING",
            "type": "space",
            "message": f"Filesystem is {df_info['use_percent']}% full",
        })

    # Check log configuration
    log_info = xfs_info.get("log", {})
    if log_info.get("blocks") and log_info.get("bsize"):
        log_size_mb = (log_info["blocks"] * log_info["bsize"]) / (1024 * 1024)
        if log_size_mb < 32:
            warnings.append({
                "severity": "WARNING",
                "type": "log",
                "message": f"Log size ({log_size_mb:.0f}MB) may be too small for optimal performance",
            })

    # Check allocation group count
    data_info = xfs_info.get("data", {})
    if data_info.get("agcount"):
        agcount = data_info.get("agcount")
        if isinstance(agcount, int) and agcount > 64:
            warnings.append({
                "severity": "INFO",
                "type": "geometry",
                "message": f"High allocation group count ({agcount}) may indicate suboptimal filesystem creation",
            })

    # Check sector size
    meta_info = xfs_info.get("meta_data", {})
    if meta_info.get("sectsz") and meta_info.get("sectsz") < 4096:
        warnings.append({
            "severity": "INFO",
            "type": "geometry",
            "message": f"Sector size {meta_info['sectsz']} may not be optimal for modern storage",
        })

    # Check mount options
    opt_issues = check_mount_options(options)
    issues.extend(opt_issues)

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
    parser = argparse.ArgumentParser(description="Monitor XFS filesystem health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show issues")
    parser.add_argument("-m", "--mount", help="Check specific mount point")
    opts = parser.parse_args(args)

    # Check for xfs_info
    if not context.check_tool("xfs_info"):
        output.error("xfs_info not found. Install xfsprogs package.")
        return 2

    # Read /proc/mounts
    try:
        mounts_content = context.read_file("/proc/mounts")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/mounts: {e}")
        return 2

    filesystems = parse_mounts(mounts_content)

    if opts.mount:
        filesystems = [fs for fs in filesystems if fs["mount_point"] == opts.mount]
        if not filesystems:
            output.error(f"{opts.mount} is not an XFS mount point")
            return 2

    if not filesystems:
        output.emit({"filesystems": [], "summary": {"total": 0}})
        if opts.format != "json" and not opts.warn_only:
            print("No XFS filesystems found")
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

        # Get xfs_info
        try:
            xfs_result = context.run(["xfs_info", fs["mount_point"]], check=False)
            if xfs_result.returncode != 0:
                result["status"] = "error"
                result["issues"].append({
                    "severity": "ERROR",
                    "type": "access",
                    "message": f"Failed to get filesystem info: {xfs_result.stderr.strip()}",
                })
                results.append(result)
                continue

            xfs_info = parse_xfs_info(xfs_result.stdout)
            result["info"]["xfs"] = xfs_info
        except Exception as e:
            result["status"] = "error"
            result["issues"].append({
                "severity": "ERROR",
                "type": "access",
                "message": str(e),
            })
            results.append(result)
            continue

        # Get df info
        try:
            df_result = context.run(["df", "-B1", fs["mount_point"]], check=False)
            if df_result.returncode == 0:
                df_info = parse_df_output(df_result.stdout)
                result["info"]["usage"] = df_info
            else:
                df_info = {}
        except Exception:
            df_info = {}

        # Analyze health
        issues, warnings = analyze_xfs_health(fs["mount_point"], xfs_info, df_info, fs["options"])
        result["issues"].extend(issues)
        result["warnings"].extend(warnings)

        # Determine status
        all_items = result["issues"] + result["warnings"]
        if any(i["severity"] == "CRITICAL" for i in all_items):
            result["status"] = "critical"
        elif any(i["severity"] in ["ERROR", "WARNING"] for i in all_items):
            result["status"] = "warning"
        elif result["issues"] or result["warnings"]:
            result["status"] = "info"
        else:
            result["status"] = "healthy"

        results.append(result)

    # Output
    has_issues = any(r["status"] in ["critical", "warning", "error"] for r in results)

    if opts.format == "json":
        json_output = {
            "filesystems": results,
            "summary": {
                "total": len(results),
                "healthy": sum(1 for r in results if r["status"] == "healthy"),
                "warning": sum(1 for r in results if r["status"] in ["warning", "info"]),
                "critical": sum(1 for r in results if r["status"] == "critical"),
                "error": sum(1 for r in results if r["status"] == "error"),
            },
        }
        if not opts.warn_only or has_issues:
            print(json.dumps(json_output, indent=2))
    else:
        if not opts.warn_only or has_issues:
            lines = []
            lines.append("XFS Health Monitor")
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
                }.get(result["status"], "[??]")

                lines.append(f"{status_icon} {result['mount_point']} ({result['device']})")

                if opts.verbose or result["status"] != "healthy":
                    usage = result.get("info", {}).get("usage", {})
                    if usage.get("use_percent"):
                        size_gb = usage.get("size_bytes", 0) / (1024**3)
                        lines.append(f"    Usage: {usage['use_percent']}% of {size_gb:.1f}GB")

                    xfs = result.get("info", {}).get("xfs", {})
                    if xfs.get("data", {}).get("agcount"):
                        lines.append(f"    Allocation groups: {xfs['data']['agcount']}")

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
                lines.append(f"[OK] All {len(results)} XFS filesystem(s) healthy")

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
