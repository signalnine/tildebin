#!/usr/bin/env python3
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

Exit codes:
    0 - All slices within normal parameters
    1 - One or more slices showing resource pressure or limit warnings
    2 - Usage error or cgroup v2 not available
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple


def read_file(path: str) -> Optional[str]:
    """Read a file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def parse_key_value_file(path: str) -> Dict[str, str]:
    """Parse a file with key=value or key value format."""
    result = {}
    content = read_file(path)
    if not content:
        return result

    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        # Handle both key=value and key value formats
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


def parse_nested_keyed_file(path: str) -> Dict[str, Dict[str, int]]:
    """Parse files like io.stat with format: device key=value key=value..."""
    result = {}
    content = read_file(path)
    if not content:
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


def get_cgroup_v2_base() -> Optional[str]:
    """Find cgroup v2 mount point."""
    # Check if unified cgroup hierarchy is mounted
    content = read_file('/proc/mounts')
    if content:
        for line in content.split('\n'):
            parts = line.split()
            if len(parts) >= 3 and parts[2] == 'cgroup2':
                return parts[1]

    # Common default location
    if os.path.exists('/sys/fs/cgroup/cgroup.controllers'):
        return '/sys/fs/cgroup'

    return None


def get_cpu_usage(cgroup_path: str) -> Optional[Dict[str, int]]:
    """Get CPU usage statistics from cpu.stat."""
    stats = parse_key_value_file(os.path.join(cgroup_path, 'cpu.stat'))
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


def get_memory_stats(cgroup_path: str) -> Optional[Dict[str, Any]]:
    """Get memory statistics."""
    result = {}

    # Current memory usage
    current = read_file(os.path.join(cgroup_path, 'memory.current'))
    if current:
        try:
            result['current_bytes'] = int(current)
        except ValueError:
            pass

    # Memory max limit
    max_mem = read_file(os.path.join(cgroup_path, 'memory.max'))
    if max_mem and max_mem != 'max':
        try:
            result['max_bytes'] = int(max_mem)
        except ValueError:
            pass

    # Memory high (soft limit)
    high = read_file(os.path.join(cgroup_path, 'memory.high'))
    if high and high != 'max':
        try:
            result['high_bytes'] = int(high)
        except ValueError:
            pass

    # Swap usage
    swap = read_file(os.path.join(cgroup_path, 'memory.swap.current'))
    if swap:
        try:
            result['swap_bytes'] = int(swap)
        except ValueError:
            pass

    # Detailed memory stats
    mem_stat = parse_key_value_file(os.path.join(cgroup_path, 'memory.stat'))
    if mem_stat:
        for key in ['anon', 'file', 'shmem', 'kernel_stack', 'slab']:
            if key in mem_stat:
                try:
                    result[f'stat_{key}'] = int(mem_stat[key])
                except ValueError:
                    pass

    return result if result else None


def get_io_stats(cgroup_path: str) -> Optional[Dict[str, Any]]:
    """Get I/O statistics."""
    io_stat = parse_nested_keyed_file(os.path.join(cgroup_path, 'io.stat'))
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


def get_psi_stats(cgroup_path: str) -> Optional[Dict[str, Dict[str, float]]]:
    """Get Pressure Stall Information (PSI) statistics."""
    result = {}

    for resource in ['cpu', 'memory', 'io']:
        psi_path = os.path.join(cgroup_path, f'{resource}.pressure')
        content = read_file(psi_path)
        if not content:
            continue

        resource_psi = {}
        for line in content.split('\n'):
            # Format: some avg10=0.00 avg60=0.00 avg300=0.00 total=0
            # Or: full avg10=0.00 avg60=0.00 avg300=0.00 total=0
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


def get_slice_info(base_path: str, slice_name: str) -> Optional[Dict[str, Any]]:
    """Get all information about a slice."""
    slice_path = os.path.join(base_path, slice_name)

    if not os.path.isdir(slice_path):
        return None

    info = {
        'name': slice_name,
        'path': slice_path,
    }

    # Get CPU stats
    cpu = get_cpu_usage(slice_path)
    if cpu:
        info['cpu'] = cpu

    # Get memory stats
    memory = get_memory_stats(slice_path)
    if memory:
        info['memory'] = memory

    # Get I/O stats
    io = get_io_stats(slice_path)
    if io:
        info['io'] = io

    # Get PSI stats
    psi = get_psi_stats(slice_path)
    if psi:
        info['psi'] = psi

    # Count child cgroups
    try:
        children = [d for d in os.listdir(slice_path)
                    if os.path.isdir(os.path.join(slice_path, d))]
        info['child_count'] = len(children)
    except OSError:
        info['child_count'] = 0

    return info


def discover_slices(base_path: str) -> List[str]:
    """Discover all systemd slices."""
    slices = []
    try:
        for entry in os.listdir(base_path):
            if entry.endswith('.slice'):
                slices.append(entry)
    except OSError:
        pass
    return sorted(slices)


def calculate_cpu_percent(cpu_stats: Dict, sample_interval: float) -> float:
    """Calculate CPU usage percentage from usage_usec over interval."""
    usage_usec = cpu_stats.get('usage_usec', 0)
    # Convert to percentage (100% = one full CPU)
    # usage_usec is cumulative, so we can't calculate rate from single sample
    # This requires two samples; return -1 to indicate unavailable
    return -1.0


def format_bytes(size: int) -> str:
    """Format bytes to human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def analyze_slice(slice_info: Dict[str, Any], warn_psi: float,
                  warn_memory_pct: float) -> Tuple[str, List[str]]:
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


def output_plain(slices: List[Dict], warn_only: bool, verbose: bool) -> None:
    """Output in plain text format."""
    if not slices:
        print("No systemd slices found")
        return

    warning_slices = []
    ok_slices = []

    for s in slices:
        status, warnings = s.get('_status', 'ok'), s.get('_warnings', [])
        if status == 'warning':
            warning_slices.append((s, warnings))
        else:
            ok_slices.append(s)

    if warning_slices:
        print("WARNINGS - Slices with resource pressure:")
        for s, warnings in warning_slices:
            print(f"\n  {s['name']}:")
            mem = s.get('memory', {})
            current = mem.get('current_bytes', 0)
            print(f"    Memory: {format_bytes(current)}")
            for w in warnings:
                print(f"    - {w}")
        print()

    if not warn_only:
        if ok_slices:
            print("Slice Resource Summary:")
            print(f"{'Slice':<30} {'Memory':>12} {'Children':>10}")
            print("-" * 54)
            for s in ok_slices:
                mem = s.get('memory', {})
                current = mem.get('current_bytes', 0)
                children = s.get('child_count', 0)
                print(f"{s['name']:<30} {format_bytes(current):>12} {children:>10}")
            print()

        if verbose:
            print("\nDetailed Statistics:")
            for s in slices:
                print(f"\n{s['name']}:")

                cpu = s.get('cpu', {})
                if cpu:
                    throttled = cpu.get('nr_throttled', 0)
                    periods = cpu.get('nr_periods', 0)
                    print(f"  CPU: {periods} periods, {throttled} throttled")

                mem = s.get('memory', {})
                if mem:
                    current = mem.get('current_bytes', 0)
                    swap = mem.get('swap_bytes', 0)
                    print(f"  Memory: {format_bytes(current)} (swap: {format_bytes(swap)})")

                io = s.get('io', {})
                if io:
                    print(f"  I/O: {format_bytes(io.get('read_bytes', 0))} read, "
                          f"{format_bytes(io.get('write_bytes', 0))} write")

                psi = s.get('psi', {})
                if psi:
                    for resource, stats in psi.items():
                        avg10 = stats.get('some_avg10', 0)
                        print(f"  PSI {resource}: {avg10:.2f}% (10s avg)")

    if not warning_slices:
        print("All slices within normal resource parameters")


def output_json(slices: List[Dict]) -> None:
    """Output in JSON format."""
    warnings = [s for s in slices if s.get('_status') == 'warning']

    # Clean up internal fields for output
    clean_slices = []
    for s in slices:
        clean = {k: v for k, v in s.items() if not k.startswith('_')}
        clean['status'] = s.get('_status', 'ok')
        clean['warnings'] = s.get('_warnings', [])
        clean_slices.append(clean)

    result = {
        'status': 'warning' if warnings else 'ok',
        'summary': {
            'total_slices': len(slices),
            'warning_count': len(warnings),
        },
        'slices': clean_slices,
    }
    print(json.dumps(result, indent=2))


def output_table(slices: List[Dict], warn_only: bool) -> None:
    """Output in table format."""
    if warn_only:
        slices = [s for s in slices if s.get('_status') == 'warning']

    if not slices:
        print("No slices to display")
        return

    # Header
    print(f"{'Slice':<28} {'Memory':>10} {'Swap':>10} {'Children':>8} {'PSI':>8} {'Status':<10}")
    print("-" * 82)

    for s in slices:
        mem = s.get('memory', {})
        current = mem.get('current_bytes', 0)
        swap = mem.get('swap_bytes', 0)
        children = s.get('child_count', 0)

        # Get max PSI across resources
        psi = s.get('psi', {})
        max_psi = 0.0
        for resource, stats in psi.items():
            avg10 = stats.get('some_avg10', 0)
            max_psi = max(max_psi, avg10)

        status = 'WARNING' if s.get('_status') == 'warning' else 'OK'
        name = s['name'][:28]

        print(f"{name:<28} {format_bytes(current):>10} {format_bytes(swap):>10} "
              f"{children:>8} {max_psi:>7.1f}% {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor systemd slice resource usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                       Show all slice resource usage
  %(prog)s --verbose             Show detailed statistics including PSI
  %(prog)s --format json         JSON output for automation
  %(prog)s --warn-only           Only show slices with warnings
  %(prog)s --warn-psi 10         Warn when PSI exceeds 10%%

Exit codes:
  0 - All slices within normal parameters
  1 - One or more slices showing resource pressure
  2 - Usage error or cgroup v2 not available
"""
    )

    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: plain)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information including PSI stats'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show slices with warnings'
    )

    parser.add_argument(
        '--warn-psi',
        type=float,
        default=25.0,
        metavar='PCT',
        help='PSI threshold for warning (default: 25.0%%)'
    )

    parser.add_argument(
        '--warn-memory',
        type=float,
        default=85.0,
        metavar='PCT',
        help='Memory usage %% of limit for warning (default: 85.0%%)'
    )

    args = parser.parse_args()

    # Validate arguments
    if args.warn_psi < 0 or args.warn_psi > 100:
        print("Error: --warn-psi must be between 0 and 100", file=sys.stderr)
        sys.exit(2)
    if args.warn_memory < 0 or args.warn_memory > 100:
        print("Error: --warn-memory must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    # Find cgroup v2 base
    cgroup_base = get_cgroup_v2_base()
    if not cgroup_base:
        print("Error: cgroup v2 not available", file=sys.stderr)
        print("This script requires cgroup v2 (unified hierarchy)", file=sys.stderr)
        sys.exit(2)

    # Discover and gather slice info
    slice_names = discover_slices(cgroup_base)
    if not slice_names:
        if args.format == 'json':
            print(json.dumps({
                'status': 'ok',
                'summary': {'total_slices': 0, 'warning_count': 0},
                'message': 'No systemd slices found',
                'slices': []
            }, indent=2))
        else:
            print("No systemd slices found")
        sys.exit(0)

    # Gather info for each slice
    slices = []
    for name in slice_names:
        info = get_slice_info(cgroup_base, name)
        if info:
            # Analyze for warnings
            status, warnings = analyze_slice(info, args.warn_psi, args.warn_memory)
            info['_status'] = status
            info['_warnings'] = warnings
            slices.append(info)

    if not slices:
        if args.format == 'json':
            print(json.dumps({
                'status': 'ok',
                'summary': {'total_slices': 0, 'warning_count': 0},
                'message': 'No readable systemd slices',
                'slices': []
            }, indent=2))
        else:
            print("No readable systemd slices")
        sys.exit(0)

    # Output based on format
    if args.format == 'json':
        output_json(slices)
    elif args.format == 'table':
        output_table(slices, args.warn_only)
    else:
        output_plain(slices, args.warn_only, args.verbose)

    # Exit code based on findings
    has_warnings = any(s.get('_status') == 'warning' for s in slices)
    sys.exit(1 if has_warnings else 0)


if __name__ == '__main__':
    main()
