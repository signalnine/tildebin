#!/usr/bin/env python3
# boxctl:
#   category: baremetal/systemd
#   tags: [systemd, slice, cgroup, resource, memory, cpu]
#   requires: []
#   privilege: none
#   related: [systemd_deps, cgroup_memory_limits, cgroup_cpu_limits, proc_pressure]
#   brief: Monitor systemd slice resource usage

"""
Monitor systemd slice resource usage for capacity planning and troubleshooting.

Tracks CPU, memory, and I/O consumption by systemd slices (user.slice,
system.slice, machine.slice, etc.) using cgroup v2 statistics. Useful for
container hosts, multi-tenant systems, and understanding resource distribution.

Key features:
- Reports CPU usage percentage per slice
- Tracks memory usage (current, max, limit)
- Monitors I/O bytes read/written
- Identifies slices approaching resource limits
- Supports cgroup v2 pressure stall information (PSI)

Use cases:
- Capacity planning for container hosts
- Identifying resource-hungry slices
- Troubleshooting performance isolation issues
- Monitoring workload distribution
"""

import argparse
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def get_cgroup_v2_base(context: Context) -> str | None:
    """Find cgroup v2 mount point."""
    try:
        content = context.read_file('/proc/mounts')
        for line in content.split('\n'):
            parts = line.split()
            if len(parts) >= 3 and parts[2] == 'cgroup2':
                return parts[1]
    except FileNotFoundError:
        pass

    # Common default location
    if context.file_exists('/sys/fs/cgroup/cgroup.controllers'):
        return '/sys/fs/cgroup'

    return None


def parse_key_value_file(context: Context, path: str) -> dict[str, str]:
    """Parse a file with key=value or key value format."""
    result = {}
    try:
        content = context.read_file(path)
    except (FileNotFoundError, PermissionError):
        return result

    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        if '=' in line:
            key, _, value = line.partition('=')
        else:
            parts = line.split(None, 1)
            if len(parts) == 2:
                key, value = parts
            elif len(parts) == 1:
                key, value = parts[0], ''
            else:
                continue
        result[key.strip()] = value.strip()

    return result


def parse_nested_keyed_file(context: Context, path: str) -> dict[str, dict[str, int]]:
    """Parse files like io.stat with format: device key=value key=value..."""
    result = {}
    try:
        content = context.read_file(path)
    except (FileNotFoundError, PermissionError):
        return result

    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        device = parts[0]
        stats = {}
        for part in parts[1:]:
            if '=' in part:
                k, _, v = part.partition('=')
                try:
                    stats[k] = int(v)
                except ValueError:
                    stats[k] = 0
        result[device] = stats

    return result


def get_cpu_usage(context: Context, cgroup_path: str) -> dict[str, int] | None:
    """Get CPU usage statistics from cpu.stat."""
    stats = parse_key_value_file(context, f'{cgroup_path}/cpu.stat')
    if not stats:
        return None

    result = {}
    for key in ['usage_usec', 'user_usec', 'system_usec', 'nr_periods',
                'nr_throttled', 'throttled_usec']:
        if key in stats:
            try:
                result[key] = int(stats[key])
            except ValueError:
                result[key] = 0

    return result if result else None


def get_memory_stats(context: Context, cgroup_path: str) -> dict[str, Any] | None:
    """Get memory statistics."""
    result = {}

    # Current memory usage
    try:
        current = context.read_file(f'{cgroup_path}/memory.current')
        result['current_bytes'] = int(current.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    # Memory max limit
    try:
        max_mem = context.read_file(f'{cgroup_path}/memory.max')
        if max_mem.strip() != 'max':
            result['max_bytes'] = int(max_mem.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    # Memory high (soft limit)
    try:
        high = context.read_file(f'{cgroup_path}/memory.high')
        if high.strip() != 'max':
            result['high_bytes'] = int(high.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    # Swap usage
    try:
        swap = context.read_file(f'{cgroup_path}/memory.swap.current')
        result['swap_bytes'] = int(swap.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        pass

    return result if result else None


def get_io_stats(context: Context, cgroup_path: str) -> dict[str, Any] | None:
    """Get I/O statistics."""
    io_stat = parse_nested_keyed_file(context, f'{cgroup_path}/io.stat')
    if not io_stat:
        return None

    # Aggregate across all devices
    total = {
        'rbytes': 0,
        'wbytes': 0,
        'rios': 0,
        'wios': 0,
    }

    for device, stats in io_stat.items():
        for key in total:
            total[key] += stats.get(key, 0)

    return {
        'read_bytes': total['rbytes'],
        'write_bytes': total['wbytes'],
        'read_ios': total['rios'],
        'write_ios': total['wios'],
        'devices': len(io_stat),
    }


def get_psi_stats(context: Context, cgroup_path: str) -> dict[str, dict[str, float]] | None:
    """Get Pressure Stall Information (PSI) statistics."""
    result = {}

    for resource in ['cpu', 'memory', 'io']:
        psi_path = f'{cgroup_path}/{resource}.pressure'
        try:
            content = context.read_file(psi_path)
        except (FileNotFoundError, PermissionError):
            continue

        resource_psi = {}
        for line in content.split('\n'):
            parts = line.split()
            if not parts:
                continue
            psi_type = parts[0]  # 'some' or 'full'
            for part in parts[1:]:
                if '=' in part:
                    key, _, value = part.partition('=')
                    try:
                        resource_psi[f'{psi_type}_{key}'] = float(value)
                    except ValueError:
                        pass

        if resource_psi:
            result[resource] = resource_psi

    return result if result else None


def discover_slices(context: Context, base_path: str) -> list[str]:
    """Discover all systemd slices."""
    slices = []
    try:
        result = context.run(['ls', base_path], check=False)
        if result.returncode == 0:
            for entry in result.stdout.strip().split('\n'):
                if entry.endswith('.slice'):
                    slices.append(entry)
    except Exception:
        pass
    return sorted(slices)


def get_slice_info(context: Context, base_path: str, slice_name: str) -> dict[str, Any] | None:
    """Get all information about a slice."""
    slice_path = f'{base_path}/{slice_name}'

    if not context.file_exists(slice_path):
        return None

    info = {
        'name': slice_name,
        'path': slice_path,
    }

    # Get CPU stats
    cpu = get_cpu_usage(context, slice_path)
    if cpu:
        info['cpu'] = cpu

    # Get memory stats
    memory = get_memory_stats(context, slice_path)
    if memory:
        info['memory'] = memory

    # Get I/O stats
    io = get_io_stats(context, slice_path)
    if io:
        info['io'] = io

    # Get PSI stats
    psi = get_psi_stats(context, slice_path)
    if psi:
        info['psi'] = psi

    return info


def format_bytes(size: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def analyze_slice(
    slice_info: dict[str, Any],
    warn_psi: float,
    warn_memory_pct: float
) -> tuple[str, list[str]]:
    """Analyze slice health and return (status, warnings)."""
    warnings = []
    status = 'ok'

    # Check memory usage vs limit
    memory = slice_info.get('memory', {})
    current = memory.get('current_bytes', 0)
    max_limit = memory.get('max_bytes')
    if max_limit and current > 0:
        pct = (current / max_limit) * 100
        if pct >= warn_memory_pct:
            warnings.append(f"Memory at {pct:.1f}% of limit")
            status = 'warning'

    # Check PSI pressure
    psi = slice_info.get('psi', {})
    for resource, stats in psi.items():
        avg10 = stats.get('some_avg10', 0)
        if avg10 >= warn_psi:
            warnings.append(f"{resource.upper()} pressure: {avg10:.1f}%")
            status = 'warning'

    # Check CPU throttling
    cpu = slice_info.get('cpu', {})
    throttled = cpu.get('nr_throttled', 0)
    periods = cpu.get('nr_periods', 0)
    if periods > 0 and throttled > 0:
        throttle_pct = (throttled / periods) * 100
        if throttle_pct > 5:
            warnings.append(f"CPU throttled {throttle_pct:.1f}% of periods")
            status = 'warning'

    return status, warnings


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
        description="Monitor systemd slice resource usage"
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information including PSI stats")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--warn-psi", type=float, default=25.0, metavar="PCT",
                        help="PSI threshold for warning (default: 25.0%%)")
    parser.add_argument("--warn-memory", type=float, default=85.0, metavar="PCT",
                        help="Memory usage %% of limit for warning (default: 85.0%%)")
    opts = parser.parse_args(args)

    # Validate arguments
    if opts.warn_psi < 0 or opts.warn_psi > 100:
        output.error("--warn-psi must be between 0 and 100")

        output.render(opts.format, "Monitor systemd slice resource usage")
        return 2
    if opts.warn_memory < 0 or opts.warn_memory > 100:
        output.error("--warn-memory must be between 0 and 100")

        output.render(opts.format, "Monitor systemd slice resource usage")
        return 2

    # Find cgroup v2 base
    cgroup_base = get_cgroup_v2_base(context)
    if not cgroup_base:
        output.error("cgroup v2 not available (requires unified hierarchy)")

        output.render(opts.format, "Monitor systemd slice resource usage")
        return 2

    # Discover and gather slice info
    slice_names = discover_slices(context, cgroup_base)
    if not slice_names:
        output.emit({
            'status': 'ok',
            'summary': {'total_slices': 0, 'warning_count': 0},
            'slices': []
        })
        output.set_summary("No systemd slices found")

        output.render(opts.format, "Monitor systemd slice resource usage")
        return 0

    # Gather info for each slice
    slices = []
    warning_count = 0
    for name in slice_names:
        info = get_slice_info(context, cgroup_base, name)
        if info:
            # Analyze for warnings
            status, warnings = analyze_slice(info, opts.warn_psi, opts.warn_memory)
            info['status'] = status
            info['warnings'] = warnings
            if status == 'warning':
                warning_count += 1
            slices.append(info)

    if not slices:
        output.emit({
            'status': 'ok',
            'summary': {'total_slices': 0, 'warning_count': 0},
            'slices': []
        })
        output.set_summary("No readable systemd slices")

        output.render(opts.format, "Monitor systemd slice resource usage")
        return 0

    # Build output
    overall_status = 'warning' if warning_count > 0 else 'ok'

    output_data = {
        'status': overall_status,
        'summary': {
            'total_slices': len(slices),
            'warning_count': warning_count,
        },
        'slices': slices if opts.verbose else [
            {
                'name': s['name'],
                'status': s['status'],
                'memory_bytes': s.get('memory', {}).get('current_bytes', 0),
                'warnings': s['warnings']
            }
            for s in slices
        ],
    }

    output.emit(output_data)

    # Set summary
    if warning_count > 0:
        output.set_summary(f"{warning_count}/{len(slices)} slices with warnings")
    else:
        output.set_summary(f"{len(slices)} slices within normal parameters")


    output.render(opts.format, "Monitor systemd slice resource usage")
    return 1 if warning_count > 0 else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
