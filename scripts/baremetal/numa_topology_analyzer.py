#!/usr/bin/env python3
# boxctl:
#   category: baremetal/numa
#   tags: [health, numa, topology, cpu, memory]
#   related: [numa_balance_monitor, memory_usage]
#   brief: Analyze NUMA topology and memory locality

"""
Analyze NUMA topology and memory locality.

Examines Non-Uniform Memory Access (NUMA) configuration to identify:
- NUMA node topology and CPU assignments
- Memory distribution across NUMA nodes
- Local vs remote memory access patterns
- NUMA balancing effectiveness
- Potential performance issues from cross-node memory access

Critical for:
- Database servers (PostgreSQL, MySQL) - memory locality affects query performance
- Virtualization hosts (KVM/QEMU) - VM placement and memory pinning
- High-performance computing - memory bandwidth optimization
- Latency-sensitive applications - reducing memory access times

Exit codes:
    0: NUMA topology healthy, good memory locality
    1: Warnings detected (imbalance, high remote access, etc.)
    2: Usage error or NUMA info unavailable
"""

import argparse

from boxctl.core.context import Context
from boxctl.core.output import Output


def parse_cpulist(content: str) -> list[int]:
    """Parse CPU list string (e.g., '0-3,8-11') into list of CPU IDs."""
    cpus = []
    if not content.strip():
        return cpus

    for part in content.strip().split(","):
        if "-" in part:
            start, end = part.split("-")
            cpus.extend(range(int(start), int(end) + 1))
        else:
            cpus.append(int(part))
    return cpus


def parse_meminfo(content: str, node_id: int) -> dict:
    """Parse NUMA node meminfo file. Returns dict with memory values in bytes."""
    result = {}

    for line in content.strip().split("\n"):
        if ":" not in line:
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        key = parts[0].split()[-1]  # Get last word before ':'
        value_parts = parts[1].strip().split()
        if value_parts:
            try:
                num = int(value_parts[0])
                if len(value_parts) > 1 and value_parts[1].lower() == "kb":
                    num *= 1024
                result[key] = num
            except ValueError:
                pass
    return result


def parse_numastat(content: str) -> dict:
    """Parse NUMA statistics file."""
    result = {}
    for line in content.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return result


def parse_vmstat(content: str) -> dict:
    """Parse /proc/vmstat for NUMA-related stats."""
    stats = {}
    for line in content.strip().split("\n"):
        if line.startswith("numa_"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    stats[parts[0]] = int(parts[1])
                except ValueError:
                    pass
    return stats


def bytes_to_human(num_bytes: int) -> str:
    """Convert bytes to human-readable format."""
    if num_bytes is None:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


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
    parser = argparse.ArgumentParser(
        description="Analyze NUMA topology and memory locality"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed info")
    parser.add_argument(
        "--format", choices=["plain", "json", "table"], default="plain", help="Output format"
    )
    parser.add_argument(
        "-w", "--warn-only", action="store_true", help="Only show output if issues detected"
    )
    opts = parser.parse_args(args)

    # Check for NUMA sysfs
    if not context.file_exists("/sys/devices/system/node"):
        output.error("NUMA sysfs not available")
        return 2

    # Find NUMA nodes
    node_dirs = context.glob("node[0-9]*", "/sys/devices/system/node")
    if not node_dirs:
        output.error("No NUMA nodes found")
        return 2

    # Extract node IDs
    node_ids = []
    for path in node_dirs:
        parts = path.split("/")
        node_name = parts[-1] if parts[-1].startswith("node") else None
        if node_name and node_name[4:].isdigit():
            node_ids.append(int(node_name[4:]))
    node_ids = sorted(node_ids)

    # Gather per-node data
    node_data = {}
    for node_id in node_ids:
        base_path = f"/sys/devices/system/node/node{node_id}"
        data = {
            "cpus": [],
            "memory": {},
            "stats": {},
        }

        # Read CPU list
        try:
            cpulist = context.read_file(f"{base_path}/cpulist")
            data["cpus"] = parse_cpulist(cpulist)
        except (FileNotFoundError, IOError):
            pass

        # Read memory info
        try:
            meminfo = context.read_file(f"{base_path}/meminfo")
            data["memory"] = parse_meminfo(meminfo, node_id)
        except (FileNotFoundError, IOError):
            pass

        # Read NUMA stats
        try:
            numastat = context.read_file(f"{base_path}/numastat")
            data["stats"] = parse_numastat(numastat)
        except (FileNotFoundError, IOError):
            pass

        node_data[node_id] = data

    # Get NUMA distances
    distances = {}
    for node_id in node_ids:
        try:
            dist_str = context.read_file(f"/sys/devices/system/node/node{node_id}/distance")
            distances[node_id] = [int(d) for d in dist_str.strip().split()]
        except (FileNotFoundError, IOError):
            pass

    # Get NUMA balancing status
    balancing = {"enabled": None, "stats": {}}
    try:
        enabled = context.read_file("/proc/sys/kernel/numa_balancing")
        balancing["enabled"] = enabled.strip() == "1"
    except (FileNotFoundError, IOError):
        pass

    try:
        vmstat = context.read_file("/proc/vmstat")
        balancing["stats"] = parse_vmstat(vmstat)
    except (FileNotFoundError, IOError):
        pass

    # Analyze topology
    issues = []
    warnings = []
    info_msgs = []

    if len(node_ids) == 1:
        info_msgs.append("Single NUMA node - no cross-node memory access concerns")
    else:
        info_msgs.append(f"Multi-NUMA system with {len(node_ids)} nodes")

        # Check memory distribution
        total_mem = 0
        node_mems = []
        for node_id in node_ids:
            mem = node_data[node_id].get("memory", {}).get("MemTotal", 0)
            node_mems.append(mem)
            total_mem += mem

        if total_mem > 0 and node_mems:
            avg_mem = total_mem / len(node_ids)
            for i, node_id in enumerate(node_ids):
                if avg_mem > 0:
                    deviation = abs(node_mems[i] - avg_mem) / avg_mem * 100
                    if deviation > 20:
                        warnings.append(
                            f"Node {node_id} memory ({bytes_to_human(node_mems[i])}) "
                            f"differs {deviation:.0f}% from average"
                        )

        # Analyze NUMA hit/miss ratios
        for node_id in node_ids:
            stats = node_data[node_id].get("stats", {})
            hits = stats.get("numa_hit", 0)
            misses = stats.get("numa_miss", 0)

            total_accesses = hits + misses
            if total_accesses > 10000:
                miss_ratio = misses / total_accesses * 100
                if miss_ratio > 30:
                    issues.append(
                        f"Node {node_id}: High NUMA miss ratio ({miss_ratio:.1f}%) - "
                        "significant cross-node memory access"
                    )
                elif miss_ratio > 10:
                    warnings.append(
                        f"Node {node_id}: Elevated NUMA miss ratio ({miss_ratio:.1f}%)"
                    )

        # Check NUMA balancing
        if balancing["enabled"] is False:
            warnings.append(
                "NUMA balancing (AutoNUMA) is disabled - "
                "memory may not be automatically migrated for locality"
            )
        elif balancing["enabled"] is True:
            info_msgs.append("NUMA balancing (AutoNUMA) is enabled")
            pages_migrated = balancing["stats"].get("numa_pages_migrated", 0)
            if pages_migrated > 1000000:
                warnings.append(
                    f"High NUMA page migration activity ({pages_migrated} pages) - "
                    "consider pinning workloads to NUMA nodes"
                )

    # Determine status
    if issues:
        status = "critical"
    elif warnings:
        status = "warning"
    else:
        status = "healthy"

    has_findings = issues or warnings

    # Build result
    result = {
        "numa_nodes": len(node_ids),
        "nodes": {str(n): node_data[n] for n in node_ids},
        "distances": distances,
        "balancing": balancing,
        "status": status,
        "issues": issues,
        "warnings": warnings,
        "info": info_msgs,
        "healthy": status == "healthy",
    }

    output.emit(result)

    # Early return for warn-only
    if opts.warn_only and not has_findings:
        return 0

    # Output
    if opts.format == "table":
        lines = []
        lines.append("+" + "-" * 62 + "+")
        lines.append("| NUMA Topology Analyzer" + " " * 39 + "|")
        lines.append("+" + "-" * 62 + "+")
        lines.append(
            f"| {'Node':<6} | {'CPUs':<8} | {'Memory':<14} | {'Used':<14} | {'Hit %':<8} |"
        )
        lines.append("+" + "-" * 62 + "+")

        for node_id in node_ids:
            data = node_data[node_id]
            cpus = len(data.get("cpus", []))
            mem = data.get("memory", {})
            stats = data.get("stats", {})

            mem_total = bytes_to_human(mem.get("MemTotal", 0))
            mem_free = mem.get("MemFree", 0)
            mem_total_raw = mem.get("MemTotal", 0)
            mem_used = (
                bytes_to_human(mem_total_raw - mem_free)
                if mem_total_raw and mem_free
                else "N/A"
            )

            hits = stats.get("numa_hit", 0)
            misses = stats.get("numa_miss", 0)
            if hits + misses > 0:
                hit_ratio = f"{hits / (hits + misses) * 100:.1f}%"
            else:
                hit_ratio = "N/A"

            lines.append(
                f"| {node_id:<6} | {cpus:<8} | {mem_total:<14} | {mem_used:<14} | {hit_ratio:<8} |"
            )

        lines.append("+" + "-" * 62 + "+")

        status_str = status.upper()
        issue_count = len(issues) + len(warnings)
        if issue_count > 0:
            status_line = f"Status: {status_str} ({issue_count} finding(s))"
        else:
            status_line = f"Status: {status_str}"
        lines.append(f"| {status_line:<60} |")
        lines.append("+" + "-" * 62 + "+")

        print("\n".join(lines))
    else:
        output.render(opts.format, "NUMA Topology Analyzer", warn_only=getattr(opts, 'warn_only', False))

    # Set summary
    output.set_summary(f"nodes={len(node_ids)}, status={status}")

    return 1 if (issues or warnings) else 0


if __name__ == "__main__":
    import sys

    sys.exit(run(sys.argv[1:], Output(), Context()))
