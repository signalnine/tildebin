#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, filesystem, nfs, storage, network]
#   brief: Monitor NFS mount health and detect issues

"""
Monitor NFS mount health on baremetal systems.

Checks NFS mount status, validates mount options, and detects:
- Soft mounts (can cause silent failures)
- Hard mounts without intr option
- Missing fstab entries
- Unmounted NFS entries in fstab

Exit codes:
    0: All NFS mounts healthy
    1: NFS mount issues detected
    2: Usage error
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


NFS_TYPES = {"nfs", "nfs4", "nfs3"}


def parse_mounts(content: str) -> list[dict]:
    """Parse /proc/mounts content for NFS mounts."""
    mounts = []
    for line in content.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]

            if fstype not in NFS_TYPES:
                continue

            mount = {
                "device": device,
                "mountpoint": mountpoint,
                "fstype": fstype,
                "options": options.split(","),
                "server": None,
                "export": None,
            }

            # Parse server:export from device
            if ":" in device:
                server_part, export_part = device.split(":", 1)
                mount["server"] = server_part
                mount["export"] = export_part

            mounts.append(mount)
    return mounts


def parse_fstab(content: str) -> list[dict]:
    """Parse /etc/fstab for NFS entries."""
    entries = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) >= 4:
            device, mountpoint, fstype, options = parts[0], parts[1], parts[2], parts[3]

            if fstype not in NFS_TYPES:
                continue

            entry = {
                "device": device,
                "mountpoint": mountpoint,
                "fstype": fstype,
                "options": options.split(","),
                "server": None,
                "export": None,
            }

            if ":" in device:
                server_part, export_part = device.split(":", 1)
                entry["server"] = server_part
                entry["export"] = export_part

            entries.append(entry)
    return entries


def analyze_mount_options(mount: dict) -> list[dict]:
    """Analyze mount options for potential issues."""
    issues = []
    options = mount["options"]

    opt_info = {
        "hard": "hard" in options,
        "soft": "soft" in options,
        "intr": "intr" in options,
    }

    # Check for soft mounts
    if opt_info["soft"]:
        issues.append({
            "severity": "WARNING",
            "type": "soft_mount",
            "message": "Soft mount detected - may cause silent failures on server issues",
        })

    # Check for hard mounts without intr
    if opt_info["hard"] and not opt_info["intr"]:
        issues.append({
            "severity": "INFO",
            "type": "no_intr",
            "message": "Hard mount without intr option - processes may become unkillable",
        })

    return issues


def analyze_nfs_health(mounts: list[dict], fstab_entries: list[dict], check_fstab: bool) -> dict:
    """Analyze NFS mount health."""
    results = {
        "mount_count": len(mounts),
        "issues": [],
        "warnings": [],
        "mounts": [],
    }

    # Analyze each mount
    for mount in mounts:
        mount_result = {
            "mountpoint": mount["mountpoint"],
            "server": mount["server"],
            "export": mount["export"],
            "fstype": mount["fstype"],
            "status": "healthy",
            "issues": [],
        }

        # Check mount options
        opt_issues = analyze_mount_options(mount)
        for issue in opt_issues:
            issue["mountpoint"] = mount["mountpoint"]
            mount_result["issues"].append(issue)
            if issue["severity"] == "WARNING":
                results["issues"].append(issue)
            else:
                results["warnings"].append(issue)

        if any(i["severity"] == "WARNING" for i in mount_result["issues"]):
            mount_result["status"] = "warning"

        results["mounts"].append(mount_result)

    # Check fstab for unmounted entries
    if check_fstab:
        mounted_points = {m["mountpoint"] for m in mounts}
        for entry in fstab_entries:
            if entry["mountpoint"] not in mounted_points:
                # Skip entries with noauto option
                if "noauto" in entry["options"]:
                    continue
                issue = {
                    "severity": "WARNING",
                    "type": "unmounted_fstab",
                    "message": f"NFS mount in fstab but not mounted: {entry['mountpoint']}",
                    "mountpoint": entry["mountpoint"],
                    "device": entry["device"],
                }
                results["issues"].append(issue)

    return results


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
    parser = argparse.ArgumentParser(description="Monitor NFS mount health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show if issues detected")
    parser.add_argument("--no-fstab", action="store_true", help="Skip fstab checks")
    opts = parser.parse_args(args)

    # Read /proc/mounts
    try:
        mounts_content = context.read_file("/proc/mounts")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/mounts: {e}")
        return 2

    mounts = parse_mounts(mounts_content)

    # Read fstab if checking
    fstab_entries = []
    if not opts.no_fstab:
        try:
            fstab_content = context.read_file("/etc/fstab")
            fstab_entries = parse_fstab(fstab_content)
        except (FileNotFoundError, IOError):
            # fstab not available is ok
            pass

    results = analyze_nfs_health(mounts, fstab_entries, not opts.no_fstab)
    has_issues = len(results["issues"]) > 0

    # Output
    if opts.format == "json":
        if not opts.warn_only or has_issues or len(mounts) == 0:
            json_output = {
                "mount_count": results["mount_count"],
                "issues": results["issues"],
                "warnings": results["warnings"],
                "healthy": not has_issues,
            }
            if opts.verbose:
                json_output["mounts"] = results["mounts"]
            print(json.dumps(json_output, indent=2))
    else:
        if not opts.warn_only or has_issues or len(mounts) == 0:
            lines = []
            lines.append("NFS Mount Health Monitor")
            lines.append("=" * 40)

            if not mounts:
                lines.append("No NFS mounts found.")
            else:
                lines.append(f"Active NFS Mounts: {len(mounts)}")
                lines.append("-" * 40)

                for mount in results["mounts"]:
                    status = "[OK]" if mount["status"] == "healthy" else "[WARN]"
                    lines.append(f"  {status} {mount['mountpoint']}")
                    lines.append(f"       Server: {mount['server']}")
                    lines.append(f"       Export: {mount['export']}")
                    lines.append(f"       Type: {mount['fstype']}")
                    if opts.verbose:
                        for issue in mount["issues"]:
                            lines.append(f"       [{issue['severity']}] {issue['message']}")
                    lines.append("")

            if results["issues"]:
                lines.append("Issues:")
                lines.append("-" * 40)
                for issue in results["issues"]:
                    lines.append(f"  [{issue['severity']}] {issue['message']}")
                lines.append("")

            if not results["issues"] and mounts:
                lines.append(f"Status: All {len(mounts)} NFS mount(s) healthy")
            elif not mounts:
                lines.append("Status: No NFS mounts to check")

            print("\n".join(lines))

    output.emit({
        "mount_count": results["mount_count"],
        "issues": results["issues"],
        "healthy": not has_issues,
    })
    output.set_summary(f"{len(mounts)} mounts, {len(results['issues'])} issues")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
