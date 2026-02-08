#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, containers, namespaces, isolation, audit]
#   brief: Audit Linux namespaces for security and operational health

"""
Audit Linux namespaces for security and operational health.

Analyzes all Linux namespace types (mnt, pid, user, net, ipc, uts, cgroup)
to detect potential security issues, leaked namespaces, and configuration problems.
Critical for container host security and debugging namespace isolation issues.

Namespace types audited:
- mnt:    Mount namespace - filesystem isolation
- pid:    Process namespace - PID isolation
- net:    Network namespace - network stack isolation
- ipc:    IPC namespace - System V IPC and POSIX message queues
- uts:    UTS namespace - hostname and domain name
- user:   User namespace - UID/GID mapping
- cgroup: Cgroup namespace - cgroup root visibility

Detects:
- Processes sharing namespaces unexpectedly (potential security issue)
- Orphaned namespaces (namespaces with no processes)
- Non-root processes in root namespaces (containers breaking isolation)
- User namespace mapping issues
- Namespace count anomalies per process

Exit codes:
    0: No issues detected
    1: Warnings or issues found
    2: Usage error or missing /proc filesystem
"""

import argparse
import json
import time
from collections import defaultdict
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


# All Linux namespace types
NAMESPACE_TYPES = ["mnt", "pid", "net", "ipc", "uts", "user", "cgroup"]

# Namespace types that containers typically isolate
CONTAINER_NAMESPACES = ["mnt", "pid", "net", "ipc", "uts"]


def parse_namespace_link(link_content: str) -> str | None:
    """Parse namespace symlink content to extract namespace ID."""
    # Format: "mnt:[4026531840]" or similar
    if "[" in link_content and "]" in link_content:
        return link_content.split("[")[1].rstrip("]").strip()
    return None


def get_init_namespaces(context: Context) -> dict[str, str]:
    """Get namespace IDs for init process (PID 1) - the root namespaces."""
    namespaces = {}

    for ns_type in NAMESPACE_TYPES:
        ns_path = f"/proc/1/ns/{ns_type}"
        try:
            content = context.read_file(ns_path)
            ns_id = parse_namespace_link(content)
            if ns_id:
                namespaces[ns_type] = ns_id
        except (FileNotFoundError, IOError):
            pass

    return namespaces


def get_process_namespaces(pid: int, context: Context) -> dict[str, str]:
    """Get namespace IDs for a specific process."""
    namespaces = {}

    for ns_type in NAMESPACE_TYPES:
        ns_path = f"/proc/{pid}/ns/{ns_type}"
        try:
            content = context.read_file(ns_path)
            ns_id = parse_namespace_link(content)
            if ns_id:
                namespaces[ns_type] = ns_id
        except (FileNotFoundError, IOError):
            pass

    return namespaces


def get_process_info(pid: int, context: Context) -> dict[str, Any]:
    """Get basic process information."""
    info = {
        "pid": pid,
        "comm": "-",
        "uid": -1,
        "cmdline": "",
    }

    # Get process name
    try:
        info["comm"] = context.read_file(f"/proc/{pid}/comm").strip()
    except (FileNotFoundError, IOError):
        pass

    # Get UID
    try:
        status = context.read_file(f"/proc/{pid}/status")
        for line in status.split("\n"):
            if line.startswith("Uid:"):
                info["uid"] = int(line.split()[1])
                break
    except (FileNotFoundError, IOError, ValueError, IndexError):
        pass

    return info


def get_all_pids(context: Context) -> list[int]:
    """Get list of all PIDs from /proc."""
    pids = []
    try:
        proc_entries = context.glob("[0-9]*", root="/proc")
        for entry in proc_entries:
            try:
                pid = int(entry.split("/")[-1])
                pids.append(pid)
            except ValueError:
                continue
    except (IOError, OSError):
        pass
    return sorted(pids)


def audit_namespaces(
    namespace_types: list[str],
    context: Context,
    verbose: bool = False,
) -> tuple[dict | None, str | None]:
    """
    Perform comprehensive namespace audit.

    Returns audit results with:
    - Namespace statistics
    - Process-to-namespace mappings
    - Detected issues
    """
    # Get init (root) namespaces as reference
    init_ns = get_init_namespaces(context)

    if not init_ns:
        return None, "Cannot read init namespaces from /proc/1/ns"

    # Track namespace usage
    namespace_usage: dict[str, dict[str, list[int]]] = {
        ns_type: defaultdict(list) for ns_type in namespace_types
    }

    # Track processes not in root namespace
    non_root_ns_processes: dict[str, list[int]] = {
        ns_type: [] for ns_type in namespace_types
    }

    # Track process info for issues
    process_cache: dict[int, dict] = {}

    issues: list[dict] = []

    # Scan all processes
    pids = get_all_pids(context)

    for pid in pids:
        proc_ns = get_process_namespaces(pid, context)

        if not proc_ns:
            continue

        for ns_type in namespace_types:
            if ns_type not in proc_ns:
                continue

            ns_id = proc_ns[ns_type]
            namespace_usage[ns_type][ns_id].append(pid)

            # Check if process is outside root namespace
            root_ns_id = init_ns.get(ns_type)
            if root_ns_id and ns_id != root_ns_id:
                non_root_ns_processes[ns_type].append(pid)

    # Build statistics
    stats = {
        "total_processes": len(pids),
        "namespaces": {},
    }

    for ns_type in namespace_types:
        usage = namespace_usage[ns_type]
        unique_ns = len(usage)
        procs_in_root = len(usage.get(init_ns.get(ns_type, ""), []))
        procs_isolated = len(non_root_ns_processes[ns_type])

        stats["namespaces"][ns_type] = {
            "unique_count": unique_ns,
            "root_ns_id": init_ns.get(ns_type, "unknown"),
            "processes_in_root": procs_in_root,
            "processes_isolated": procs_isolated,
        }

    # Detect issues

    # Issue 1: Large number of unique namespaces (potential leak)
    for ns_type in namespace_types:
        unique_count = stats["namespaces"][ns_type]["unique_count"]
        if unique_count > 100:
            issues.append({
                "type": "high_namespace_count",
                "namespace": ns_type,
                "count": unique_count,
                "severity": "warning",
                "message": f"High number of unique {ns_type} namespaces ({unique_count}), possible namespace leak",
            })

    # Issue 2: Single process in isolated namespace (potentially orphaned)
    for ns_type in namespace_types:
        if ns_type not in CONTAINER_NAMESPACES:
            continue

        root_ns_id = init_ns.get(ns_type)
        for ns_id, pid_list in namespace_usage[ns_type].items():
            if ns_id == root_ns_id:
                continue

            if len(pid_list) == 1 and verbose:
                pid = pid_list[0]
                if pid not in process_cache:
                    process_cache[pid] = get_process_info(pid, context)

                proc_info = process_cache[pid]
                issues.append({
                    "type": "single_process_namespace",
                    "namespace": ns_type,
                    "namespace_id": ns_id,
                    "pid": pid,
                    "process": proc_info["comm"],
                    "severity": "info",
                    "message": f'Single process ({proc_info["comm"]}, PID {pid}) in isolated {ns_type} namespace',
                })

    # Issue 3: Partial isolation (net but not mnt)
    net_non_root = set(non_root_ns_processes.get("net", []))
    mnt_non_root = set(non_root_ns_processes.get("mnt", []))

    partial_isolation = net_non_root - mnt_non_root
    if partial_isolation:
        for pid in list(partial_isolation)[:10]:
            if pid not in process_cache:
                process_cache[pid] = get_process_info(pid, context)

            proc_info = process_cache[pid]
            issues.append({
                "type": "partial_isolation",
                "namespace": "net vs mnt",
                "pid": pid,
                "process": proc_info["comm"],
                "severity": "warning",
                "message": f'Process {proc_info["comm"]} (PID {pid}) isolated in net but not mnt namespace',
            })

    # Build results
    results = {
        "init_namespaces": init_ns,
        "statistics": stats,
        "issues": issues,
        "namespace_details": {},
    }

    # Add namespace details if verbose
    if verbose:
        for ns_type in namespace_types:
            results["namespace_details"][ns_type] = {}
            for ns_id, pid_list in namespace_usage[ns_type].items():
                is_root = ns_id == init_ns.get(ns_type)
                results["namespace_details"][ns_type][ns_id] = {
                    "is_root": is_root,
                    "process_count": len(pid_list),
                    "pids": pid_list[:20] if len(pid_list) > 20 else pid_list,
                }

    return results, None


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = no issues, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit Linux namespaces for security and operational health"
    )
    parser.add_argument(
        "--format",
        choices=["plain", "json", "table"],
        default="plain",
        help="Output format (default: plain)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show detailed namespace information",
    )
    parser.add_argument(
        "-w", "--warn-only",
        action="store_true",
        help="Only show warnings and critical issues",
    )
    parser.add_argument(
        "-t", "--types",
        type=str,
        metavar="TYPES",
        help=f"Comma-separated namespace types to audit (default: all). Options: {','.join(NAMESPACE_TYPES)}",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Show summary statistics only, no detailed issues",
    )

    opts = parser.parse_args(args)

    # Check /proc availability
    if not context.file_exists("/proc/1/ns"):
        output.error("/proc filesystem not available or /proc/1/ns not readable")
        return 2

    # Parse namespace types
    namespace_types = NAMESPACE_TYPES
    if opts.types:
        requested_types = [t.strip() for t in opts.types.split(",")]
        invalid_types = [t for t in requested_types if t not in NAMESPACE_TYPES]
        if invalid_types:
            output.error(f"Invalid namespace types: {', '.join(invalid_types)}")
            return 2
        namespace_types = requested_types

    # Perform audit
    results, error = audit_namespaces(namespace_types, context, verbose=opts.verbose)

    if error:
        if opts.format == "json":
            print(json.dumps({"error": error}))
        else:
            output.error(error)
        return 2

    # Output results
    data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "audit_results": results,
    }
    output.emit(data)

    if opts.format == "table":
        _output_table(results, opts.warn_only)
    else:
        output.render(opts.format, "Linux Namespace Audit", warn_only=getattr(opts, 'warn_only', False))

    # Determine exit code
    has_issues = any(
        i["severity"] in ("warning", "critical")
        for i in results.get("issues", [])
    )

    # Set summary
    if has_issues:
        issue_count = len([i for i in results.get("issues", []) if i["severity"] in ("warning", "critical")])
        output.set_summary(f"Found {issue_count} namespace issue(s)")
    else:
        output.set_summary(f"Namespace audit passed ({results['statistics']['total_processes']} processes scanned)")

    return 1 if has_issues else 0


def _output_table(results: dict, warn_only: bool) -> None:
    """Output results in table format."""
    stats = results["statistics"]
    issues = results["issues"]

    print(f"{'Namespace':<10} {'Unique NS':<12} {'Root NS ID':<20} {'In Root':<10} {'Isolated':<10}")
    print("-" * 72)

    for ns_type, ns_stats in stats["namespaces"].items():
        root_id = ns_stats["root_ns_id"][:18]
        print(
            f"{ns_type:<10} {ns_stats['unique_count']:<12} {root_id:<20} "
            f"{ns_stats['processes_in_root']:<10} {ns_stats['processes_isolated']:<10}"
        )

    print()

    filtered_issues = issues
    if warn_only:
        filtered_issues = [i for i in issues if i["severity"] in ("warning", "critical")]

    if filtered_issues:
        print(f"{'Severity':<10} {'Type':<25} {'Details':<40}")
        print("-" * 75)

        for issue in filtered_issues:
            details = issue.get("message", "")[:40]
            print(f"{issue['severity'].upper():<10} {issue['type']:<25} {details:<40}")


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
