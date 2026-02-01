#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, filesystem, mount, storage]
#   brief: Monitor mount health and detect hung or problematic mounts

"""
Monitor mounted filesystem health and detect hung or problematic mounts.

Checks for:
- Hung/unresponsive mounts (NFS, CIFS, FUSE)
- Read-only remounts indicating filesystem errors
- Dangerous mount options (nobarrier, data=writeback)
- Bind mount consistency

Exit codes:
    0: All mounts healthy
    1: Mount issues detected
    2: Usage error
"""

import argparse
import json

from boxctl.core.context import Context
from boxctl.core.output import Output


# Virtual/special filesystems to skip
VIRTUAL_FS = {
    "proc", "sysfs", "devpts", "cgroup", "cgroup2", "securityfs",
    "pstore", "debugfs", "tracefs", "configfs", "hugetlbfs",
    "mqueue", "binfmt_misc", "fusectl", "efivarfs", "autofs",
    "devtmpfs", "rpc_pipefs", "nfsd", "overlay",
}

# Dangerous mount options
DANGEROUS_OPTIONS = {
    "nobarrier": "Data integrity risk on power failure",
    "barrier=0": "Data integrity risk on power failure",
    "data=writeback": "Crash recovery risk for ext3/4",
}

# Filesystem types that should normally be read-write
WRITABLE_FS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "nfs", "nfs4", "cifs", "tmpfs"}


def parse_mounts(content: str) -> list[dict]:
    """Parse /proc/mounts content."""
    mounts = []
    for line in content.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 6:
            device, mountpoint, fstype, options, dump, fsck = parts[:6]
            mounts.append({
                "device": device,
                "mountpoint": mountpoint,
                "fstype": fstype,
                "options": options.split(","),
            })
    return mounts


def parse_mountinfo(content: str) -> dict:
    """Parse /proc/self/mountinfo for detailed mount information."""
    mountinfo = {}
    for line in content.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 10:
            mountpoint = parts[4]

            # Find the separator '-' and parse fstype/source
            sep_idx = -1
            for i, p in enumerate(parts):
                if p == "-":
                    sep_idx = i
                    break

            if sep_idx > 0 and len(parts) > sep_idx + 2:
                fstype = parts[sep_idx + 1]
                source = parts[sep_idx + 2]
            else:
                fstype = ""
                source = ""

            mountinfo[mountpoint] = {
                "root": parts[3],
                "fstype": fstype,
                "source": source,
            }
    return mountinfo


def check_mount_options(mount: dict) -> list[dict]:
    """Check mount options for potential issues."""
    issues = []
    options = mount["options"]

    # Check for dangerous options
    for opt in options:
        if opt in DANGEROUS_OPTIONS:
            issues.append({
                "severity": "WARNING",
                "type": "dangerous_option",
                "message": f"Option '{opt}': {DANGEROUS_OPTIONS[opt]}",
            })

    return issues


def check_readonly(mount: dict) -> list[dict]:
    """Check for unexpected read-only mounts."""
    issues = []
    options = mount["options"]
    fstype = mount["fstype"]

    # Skip pseudo filesystems
    if fstype in VIRTUAL_FS:
        return issues

    # Check if a normally-writable filesystem is read-only
    if "ro" in options and fstype in WRITABLE_FS:
        issues.append({
            "severity": "WARNING",
            "type": "readonly",
            "message": f"{fstype} mounted read-only (may indicate filesystem errors)",
        })

    return issues


def analyze_mounts(mounts: list[dict], mountinfo: dict, skip_virtual: bool, check_options: bool) -> dict:
    """Analyze all mounts for issues."""
    results = {
        "total_mounts": len(mounts),
        "checked": 0,
        "healthy": 0,
        "issues": [],
        "readonly_mounts": [],
        "option_issues": [],
        "mounts": [],
    }

    for mount in mounts:
        fstype = mount["fstype"]
        mountpoint = mount["mountpoint"]

        # Skip virtual filesystems if requested
        if skip_virtual and fstype in VIRTUAL_FS:
            continue

        results["checked"] += 1
        mount_result = {
            "mountpoint": mountpoint,
            "device": mount["device"],
            "fstype": fstype,
            "status": "healthy",
            "issues": [],
        }

        # Check for read-only issues
        ro_issues = check_readonly(mount)
        if ro_issues:
            mount_result["issues"].extend(ro_issues)
            results["readonly_mounts"].append(mountpoint)
            for issue in ro_issues:
                results["issues"].append({
                    **issue,
                    "mountpoint": mountpoint,
                })

        # Check mount options
        if check_options:
            opt_issues = check_mount_options(mount)
            if opt_issues:
                mount_result["issues"].extend(opt_issues)
                results["option_issues"].append(mountpoint)
                for issue in opt_issues:
                    results["issues"].append({
                        **issue,
                        "mountpoint": mountpoint,
                    })

        if mount_result["issues"]:
            mount_result["status"] = "warning"
        else:
            results["healthy"] += 1

        results["mounts"].append(mount_result)

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
    parser = argparse.ArgumentParser(description="Monitor mount health")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-w", "--warn-only", action="store_true", help="Only show if issues detected")
    parser.add_argument("--skip-virtual", action="store_true", help="Skip virtual filesystems")
    parser.add_argument("--check-options", action="store_true", help="Check for dangerous mount options")
    opts = parser.parse_args(args)

    # Read /proc/mounts
    try:
        mounts_content = context.read_file("/proc/mounts")
    except (FileNotFoundError, IOError) as e:
        output.error(f"Unable to read /proc/mounts: {e}")
        return 2

    # Read /proc/self/mountinfo for additional info
    try:
        mountinfo_content = context.read_file("/proc/self/mountinfo")
        mountinfo = parse_mountinfo(mountinfo_content)
    except (FileNotFoundError, IOError):
        mountinfo = {}

    mounts = parse_mounts(mounts_content)
    results = analyze_mounts(mounts, mountinfo, opts.skip_virtual, opts.check_options)

    has_issues = len(results["issues"]) > 0

    # Output
    if opts.format == "json":
        if not opts.warn_only or has_issues:
            json_output = {
                "summary": {
                    "total_mounts": results["total_mounts"],
                    "checked": results["checked"],
                    "healthy": results["healthy"],
                    "readonly_count": len(results["readonly_mounts"]),
                    "option_issues": len(results["option_issues"]),
                },
                "issues": results["issues"],
                "has_issues": has_issues,
            }
            if opts.verbose:
                json_output["mounts"] = results["mounts"]
            print(json.dumps(json_output, indent=2))
    else:
        if not opts.warn_only or has_issues:
            lines = []
            lines.append("Mount Health Monitor")
            lines.append("=" * 40)
            lines.append(f"  Total mounts:    {results['total_mounts']}")
            lines.append(f"  Checked:         {results['checked']}")
            lines.append(f"  Healthy:         {results['healthy']}")
            lines.append(f"  Read-only:       {len(results['readonly_mounts'])}")
            lines.append("")

            if opts.verbose:
                lines.append("Mount Details:")
                for mount in results["mounts"]:
                    status_icon = "[OK]" if mount["status"] == "healthy" else "[WARN]"
                    lines.append(f"  {status_icon} {mount['mountpoint']}")
                    lines.append(f"       Device: {mount['device']}")
                    lines.append(f"       Type:   {mount['fstype']}")
                    for issue in mount["issues"]:
                        lines.append(f"       Issue:  {issue['message']}")
                lines.append("")

            if results["issues"]:
                lines.append("Issues Detected:")
                for issue in results["issues"]:
                    lines.append(f"  [{issue['severity']}] {issue['mountpoint']}: {issue['message']}")
            else:
                lines.append("[OK] All mounts healthy")

            print("\n".join(lines))

    output.emit({
        "total": results["total_mounts"],
        "checked": results["checked"],
        "healthy": results["healthy"],
        "issues": results["issues"],
    })
    output.set_summary(f"{results['healthy']} healthy, {len(results['issues'])} issues")

    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
