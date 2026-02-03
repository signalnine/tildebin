#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [socket, buffer, memory, network, tcp, udp]
#   requires: []
#   privilege: none
#   related: [socket_queue, tcp_connection_monitor, softnet_backlog_monitor]
#   brief: Monitor socket buffer usage and memory pressure

"""
Monitor socket buffer usage and memory pressure for baremetal systems.

Socket buffers (rmem/wmem) are critical for network performance. When buffers
are undersized or exhausted, packets may be dropped or connections throttled.
This script monitors socket buffer memory usage and configuration, identifying
potential bottlenecks before they impact network performance.

Key features:
- Reports current socket buffer memory usage vs configured limits
- Identifies protocols with high buffer pressure
- Detects when socket memory is near limits
- Shows per-protocol socket counts and memory usage
- Useful for tuning tcp_rmem/tcp_wmem sysctl settings
"""

import argparse
import os
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


PROC_PATHS = {
    'sockstat': '/proc/net/sockstat',
    'sockstat6': '/proc/net/sockstat6',
    'rmem_default': '/proc/sys/net/core/rmem_default',
    'rmem_max': '/proc/sys/net/core/rmem_max',
    'wmem_default': '/proc/sys/net/core/wmem_default',
    'wmem_max': '/proc/sys/net/core/wmem_max',
    'tcp_mem': '/proc/sys/net/ipv4/tcp_mem',
    'tcp_rmem': '/proc/sys/net/ipv4/tcp_rmem',
    'tcp_wmem': '/proc/sys/net/ipv4/tcp_wmem',
    'udp_mem': '/proc/sys/net/ipv4/udp_mem',
    'optmem_max': '/proc/sys/net/core/optmem_max',
}


def read_sysctl_value(context: Context, path: str) -> int | None:
    """Read a sysctl value and return as integer."""
    try:
        content = context.read_file(path)
        return int(content.strip())
    except (FileNotFoundError, ValueError, PermissionError):
        return None


def read_sysctl_triple(context: Context, path: str) -> list[int] | None:
    """Read a sysctl with three space-separated values (min, default, max)."""
    try:
        content = context.read_file(path)
        parts = content.strip().split()
        if len(parts) >= 3:
            return [int(parts[0]), int(parts[1]), int(parts[2])]
    except (FileNotFoundError, ValueError, PermissionError):
        pass
    return None


def parse_sockstat(content: str) -> dict[str, dict[str, int]]:
    """Parse /proc/net/sockstat or sockstat6 format."""
    stats = {}
    for line in content.split('\n'):
        if not line or ':' not in line:
            continue
        proto, rest = line.split(':', 1)
        proto = proto.strip().upper()
        pairs = rest.strip().split()
        proto_stats = {}
        i = 0
        while i < len(pairs) - 1:
            key = pairs[i]
            try:
                value = int(pairs[i + 1])
                proto_stats[key] = value
                i += 2
            except ValueError:
                i += 1
        if proto_stats:
            stats[proto] = proto_stats
    return stats


def get_socket_stats(context: Context) -> dict[str, dict[str, int]]:
    """Get socket statistics from /proc/net/sockstat and sockstat6."""
    stats = {}

    try:
        content = context.read_file(PROC_PATHS['sockstat'])
        stats.update(parse_sockstat(content))
    except FileNotFoundError:
        pass

    try:
        content6 = context.read_file(PROC_PATHS['sockstat6'])
        ipv6_stats = parse_sockstat(content6)
        for proto, values in ipv6_stats.items():
            stats[f'{proto}6'] = values
    except FileNotFoundError:
        pass

    return stats


def get_buffer_config(context: Context) -> dict[str, Any]:
    """Get socket buffer configuration from sysctl."""
    config = {}
    config['rmem_default'] = read_sysctl_value(context, PROC_PATHS['rmem_default'])
    config['rmem_max'] = read_sysctl_value(context, PROC_PATHS['rmem_max'])
    config['wmem_default'] = read_sysctl_value(context, PROC_PATHS['wmem_default'])
    config['wmem_max'] = read_sysctl_value(context, PROC_PATHS['wmem_max'])
    config['tcp_mem'] = read_sysctl_triple(context, PROC_PATHS['tcp_mem'])
    config['tcp_rmem'] = read_sysctl_triple(context, PROC_PATHS['tcp_rmem'])
    config['tcp_wmem'] = read_sysctl_triple(context, PROC_PATHS['tcp_wmem'])
    config['udp_mem'] = read_sysctl_triple(context, PROC_PATHS['udp_mem'])
    config['optmem_max'] = read_sysctl_value(context, PROC_PATHS['optmem_max'])
    return config


def get_page_size() -> int:
    """Get system page size in bytes."""
    try:
        return os.sysconf('SC_PAGESIZE')
    except (ValueError, OSError):
        return 4096


def format_bytes(num_bytes: int) -> str:
    """Format bytes to human-readable format."""
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024 * 1024):.1f} GB"
    elif num_bytes >= 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MB"
    elif num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f} KB"
    else:
        return f"{num_bytes} B"


def analyze_pressure(
    stats: dict,
    config: dict,
    page_size: int,
    warn_threshold: float,
    crit_threshold: float
) -> dict[str, Any]:
    """Analyze socket buffer pressure."""
    analysis = {
        'issues': [],
        'warnings': [],
        'protocols': {},
    }

    # Analyze TCP memory pressure
    tcp_stats = stats.get('TCP', {})
    tcp_mem_pages = tcp_stats.get('mem', 0)
    tcp_mem_bytes = tcp_mem_pages * page_size

    if config.get('tcp_mem') and tcp_mem_pages > 0:
        tcp_min, tcp_pressure, tcp_max = config['tcp_mem']
        tcp_max_bytes = tcp_max * page_size
        usage_pct = (tcp_mem_pages / tcp_max) * 100 if tcp_max > 0 else 0

        analysis['protocols']['TCP'] = {
            'memory_pages': tcp_mem_pages,
            'memory_bytes': tcp_mem_bytes,
            'limit_pages': tcp_max,
            'limit_bytes': tcp_max_bytes,
            'usage_pct': round(usage_pct, 1),
            'inuse': tcp_stats.get('inuse', 0),
            'orphan': tcp_stats.get('orphan', 0),
            'tw': tcp_stats.get('tw', 0),
            'alloc': tcp_stats.get('alloc', 0),
        }

        if usage_pct >= crit_threshold:
            analysis['issues'].append({
                'protocol': 'TCP',
                'severity': 'critical',
                'message': f'TCP memory at {usage_pct:.1f}% of limit ({format_bytes(tcp_mem_bytes)}/{format_bytes(tcp_max_bytes)})',
            })
        elif usage_pct >= warn_threshold:
            analysis['warnings'].append({
                'protocol': 'TCP',
                'severity': 'warning',
                'message': f'TCP memory at {usage_pct:.1f}% of limit ({format_bytes(tcp_mem_bytes)}/{format_bytes(tcp_max_bytes)})',
            })

        if tcp_mem_pages >= tcp_pressure:
            analysis['issues'].append({
                'protocol': 'TCP',
                'severity': 'critical',
                'message': f'TCP memory exceeds pressure threshold ({tcp_mem_pages} >= {tcp_pressure} pages)',
            })

    # Analyze UDP memory pressure
    udp_stats = stats.get('UDP', {})
    udp_mem_pages = udp_stats.get('mem', 0)
    udp_mem_bytes = udp_mem_pages * page_size

    if config.get('udp_mem') and udp_mem_pages > 0:
        udp_min, udp_pressure, udp_max = config['udp_mem']
        udp_max_bytes = udp_max * page_size
        usage_pct = (udp_mem_pages / udp_max) * 100 if udp_max > 0 else 0

        analysis['protocols']['UDP'] = {
            'memory_pages': udp_mem_pages,
            'memory_bytes': udp_mem_bytes,
            'limit_pages': udp_max,
            'limit_bytes': udp_max_bytes,
            'usage_pct': round(usage_pct, 1),
            'inuse': udp_stats.get('inuse', 0),
        }

        if usage_pct >= crit_threshold:
            analysis['issues'].append({
                'protocol': 'UDP',
                'severity': 'critical',
                'message': f'UDP memory at {usage_pct:.1f}% of limit',
            })
        elif usage_pct >= warn_threshold:
            analysis['warnings'].append({
                'protocol': 'UDP',
                'severity': 'warning',
                'message': f'UDP memory at {usage_pct:.1f}% of limit',
            })

    # Check for high orphan sockets
    orphan_count = tcp_stats.get('orphan', 0)
    if orphan_count > 1000:
        analysis['warnings'].append({
            'protocol': 'TCP',
            'severity': 'warning',
            'message': f'High orphan socket count: {orphan_count}',
        })

    # Check for high TIME_WAIT sockets
    tw_count = tcp_stats.get('tw', 0)
    if tw_count > 10000:
        analysis['warnings'].append({
            'protocol': 'TCP',
            'severity': 'warning',
            'message': f'High TIME_WAIT socket count: {tw_count}',
        })

    # Add other protocols
    for proto in ['UDPLITE', 'RAW', 'FRAG', 'TCP6', 'UDP6', 'UDPLITE6', 'RAW6', 'FRAG6']:
        if proto in stats:
            proto_stats = stats[proto]
            analysis['protocols'][proto] = {
                'inuse': proto_stats.get('inuse', 0),
                'memory_pages': proto_stats.get('mem', 0),
            }

    return analysis


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
    parser = argparse.ArgumentParser(description="Monitor socket buffer usage and memory pressure")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--warn", type=float, default=70.0, metavar="PCT",
                        help="Warning threshold percentage (default: 70)")
    parser.add_argument("--crit", type=float, default=85.0, metavar="PCT",
                        help="Critical threshold percentage (default: 85)")
    opts = parser.parse_args(args)

    # Validate thresholds
    if opts.warn < 0 or opts.warn > 100:
        output.error("--warn must be 0-100")

        output.render(opts.format, "Monitor socket buffer usage and memory pressure")
        return 2
    if opts.crit < 0 or opts.crit > 100:
        output.error("--crit must be 0-100")

        output.render(opts.format, "Monitor socket buffer usage and memory pressure")
        return 2
    if opts.warn >= opts.crit:
        output.error("--warn must be less than --crit")

        output.render(opts.format, "Monitor socket buffer usage and memory pressure")
        return 2

    # Check for /proc filesystem
    if not context.file_exists(PROC_PATHS['sockstat']):
        output.error("/proc/net/sockstat not available")

        output.render(opts.format, "Monitor socket buffer usage and memory pressure")
        return 2

    # Collect data
    page_size = get_page_size()
    stats = get_socket_stats(context)
    config = get_buffer_config(context)

    if not stats:
        output.warning("No socket statistics found")
        output.emit({'protocols': {}, 'issues': [], 'warnings': []})

        output.render(opts.format, "Monitor socket buffer usage and memory pressure")
        return 1

    # Analyze
    analysis = analyze_pressure(stats, config, page_size, opts.warn, opts.crit)

    # Build result
    result = {
        'status': 'ok',
        'page_size_bytes': page_size,
        'protocols': analysis['protocols'],
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'config': {k: v for k, v in config.items() if v is not None},
    }

    if analysis['issues']:
        result['status'] = 'critical'
    elif analysis['warnings']:
        result['status'] = 'warning'

    output.emit(result)

    # Set summary
    issue_count = len(analysis['issues'])
    warning_count = len(analysis['warnings'])
    if issue_count > 0:
        output.set_summary(f"{issue_count} critical issues, {warning_count} warnings")
    elif warning_count > 0:
        output.set_summary(f"{warning_count} warnings")
    else:
        output.set_summary("No socket buffer pressure detected")

    # Return exit code
    if analysis['issues'] or analysis['warnings']:

        output.render(opts.format, "Monitor socket buffer usage and memory pressure")
        return 1

    output.render(opts.format, "Monitor socket buffer usage and memory pressure")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
