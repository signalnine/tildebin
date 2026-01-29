#!/usr/bin/env python3
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

Monitored sources:
- /proc/net/sockstat  - Socket statistics by protocol
- /proc/net/sockstat6 - IPv6 socket statistics
- /proc/sys/net/core/rmem_* - Receive buffer limits
- /proc/sys/net/core/wmem_* - Send buffer limits
- /proc/sys/net/ipv4/tcp_mem - TCP memory limits

Exit codes:
    0 - No socket buffer pressure detected
    1 - Socket buffer pressure or warnings detected
    2 - Usage error or /proc filesystem not available
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional


def read_proc_file(path: str) -> Optional[str]:
    """Read a /proc file and return contents."""
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (OSError, IOError, PermissionError):
        return None


def read_sysctl_value(path: str) -> Optional[int]:
    """Read a sysctl value and return as integer."""
    content = read_proc_file(path)
    if content:
        try:
            return int(content.strip())
        except ValueError:
            pass
    return None


def read_sysctl_triple(path: str) -> Optional[List[int]]:
    """Read a sysctl with three space-separated values (min, default, max)."""
    content = read_proc_file(path)
    if content:
        try:
            parts = content.strip().split()
            if len(parts) >= 3:
                return [int(parts[0]), int(parts[1]), int(parts[2])]
        except ValueError:
            pass
    return None


def parse_sockstat(content: str) -> Dict[str, Dict[str, int]]:
    """Parse /proc/net/sockstat or sockstat6 format.

    Example format:
        sockets: used 1234
        TCP: inuse 100 orphan 0 tw 50 alloc 150 mem 1000
        UDP: inuse 20 mem 10
        ...
    """
    stats = {}

    for line in content.split('\n'):
        if not line or ':' not in line:
            continue

        proto, rest = line.split(':', 1)
        proto = proto.strip().upper()

        pairs = rest.strip().split()
        proto_stats = {}

        # Parse key-value pairs
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


def get_socket_stats() -> Dict[str, Dict[str, int]]:
    """Get socket statistics from /proc/net/sockstat and sockstat6."""
    stats = {}

    # IPv4 socket stats
    content = read_proc_file('/proc/net/sockstat')
    if content:
        stats.update(parse_sockstat(content))

    # IPv6 socket stats
    content6 = read_proc_file('/proc/net/sockstat6')
    if content6:
        ipv6_stats = parse_sockstat(content6)
        # Merge with suffix for IPv6
        for proto, values in ipv6_stats.items():
            stats[f'{proto}6'] = values

    return stats


def get_buffer_config() -> Dict[str, Any]:
    """Get socket buffer configuration from sysctl."""
    config = {}

    # Core buffer limits
    config['rmem_default'] = read_sysctl_value('/proc/sys/net/core/rmem_default')
    config['rmem_max'] = read_sysctl_value('/proc/sys/net/core/rmem_max')
    config['wmem_default'] = read_sysctl_value('/proc/sys/net/core/wmem_default')
    config['wmem_max'] = read_sysctl_value('/proc/sys/net/core/wmem_max')

    # TCP memory limits (in pages)
    config['tcp_mem'] = read_sysctl_triple('/proc/sys/net/ipv4/tcp_mem')
    config['tcp_rmem'] = read_sysctl_triple('/proc/sys/net/ipv4/tcp_rmem')
    config['tcp_wmem'] = read_sysctl_triple('/proc/sys/net/ipv4/tcp_wmem')

    # UDP memory limit
    config['udp_mem'] = read_sysctl_triple('/proc/sys/net/ipv4/udp_mem')

    # Optmem (ancillary buffer)
    config['optmem_max'] = read_sysctl_value('/proc/sys/net/core/optmem_max')

    return config


def get_page_size() -> int:
    """Get system page size in bytes."""
    try:
        return os.sysconf('SC_PAGESIZE')
    except (ValueError, OSError):
        return 4096  # Default fallback


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


def analyze_pressure(stats: Dict, config: Dict, page_size: int,
                     warn_threshold: float, crit_threshold: float) -> Dict[str, Any]:
    """Analyze socket buffer pressure.

    Args:
        stats: Socket statistics from /proc/net/sockstat
        config: Buffer configuration from sysctl
        page_size: System page size in bytes
        warn_threshold: Warning threshold percentage (0-100)
        crit_threshold: Critical threshold percentage (0-100)

    Returns:
        Analysis results with pressure status
    """
    analysis = {
        'issues': [],
        'warnings': [],
        'info': [],
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

        # Check for pressure threshold (when kernel starts dropping packets)
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

    # Check for high orphan sockets (connection issues)
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

    # Add other protocols for completeness
    for proto in ['UDPLITE', 'RAW', 'FRAG', 'TCP6', 'UDP6', 'UDPLITE6', 'RAW6', 'FRAG6']:
        if proto in stats:
            proto_stats = stats[proto]
            analysis['protocols'][proto] = {
                'inuse': proto_stats.get('inuse', 0),
                'memory_pages': proto_stats.get('mem', 0),
            }

    return analysis


def output_plain(stats: Dict, config: Dict, analysis: Dict,
                 page_size: int, verbose: bool, warn_only: bool) -> None:
    """Output results in plain text format."""
    if warn_only and not analysis['issues'] and not analysis['warnings']:
        return

    print("Socket Buffer Monitor")
    print("=" * 60)
    print()

    # Show issues first
    if analysis['issues']:
        print("CRITICAL ISSUES:")
        for issue in analysis['issues']:
            print(f"  [!!] {issue['message']}")
        print()

    if analysis['warnings']:
        print("WARNINGS:")
        for warning in analysis['warnings']:
            print(f"  [!] {warning['message']}")
        print()

    if not warn_only:
        # Protocol summary
        print("Protocol Status:")
        print("-" * 60)
        print(f"{'Protocol':<12} {'In-use':<10} {'Memory':<12} {'Usage':<10} {'Limit':<12}")
        print("-" * 60)

        for proto, data in analysis['protocols'].items():
            inuse = data.get('inuse', 0)
            mem_bytes = data.get('memory_bytes', data.get('memory_pages', 0) * page_size)
            usage_pct = data.get('usage_pct', 0)
            limit_bytes = data.get('limit_bytes', 0)

            mem_str = format_bytes(mem_bytes) if mem_bytes else '-'
            usage_str = f"{usage_pct:.1f}%" if usage_pct else '-'
            limit_str = format_bytes(limit_bytes) if limit_bytes else '-'

            print(f"{proto:<12} {inuse:<10} {mem_str:<12} {usage_str:<10} {limit_str:<12}")

        print()

        if verbose:
            # Show buffer configuration
            print("Buffer Configuration:")
            print("-" * 60)
            if config.get('rmem_default'):
                print(f"  Receive buffer default: {format_bytes(config['rmem_default'])}")
            if config.get('rmem_max'):
                print(f"  Receive buffer max: {format_bytes(config['rmem_max'])}")
            if config.get('wmem_default'):
                print(f"  Send buffer default: {format_bytes(config['wmem_default'])}")
            if config.get('wmem_max'):
                print(f"  Send buffer max: {format_bytes(config['wmem_max'])}")

            if config.get('tcp_rmem'):
                min_b, def_b, max_b = config['tcp_rmem']
                print(f"  TCP receive buffer: {format_bytes(min_b)} / {format_bytes(def_b)} / {format_bytes(max_b)}")
            if config.get('tcp_wmem'):
                min_b, def_b, max_b = config['tcp_wmem']
                print(f"  TCP send buffer: {format_bytes(min_b)} / {format_bytes(def_b)} / {format_bytes(max_b)}")

            if config.get('tcp_mem'):
                min_p, pres_p, max_p = config['tcp_mem']
                print(f"  TCP memory limits: {min_p} / {pres_p} / {max_p} pages")
                print(f"                     ({format_bytes(min_p * page_size)} / {format_bytes(pres_p * page_size)} / {format_bytes(max_p * page_size)})")
            print()

            # TCP details
            tcp_proto = analysis['protocols'].get('TCP', {})
            if tcp_proto:
                print("TCP Socket Details:")
                print(f"  Active connections: {tcp_proto.get('inuse', 0)}")
                print(f"  Allocated sockets: {tcp_proto.get('alloc', 0)}")
                print(f"  Orphaned sockets: {tcp_proto.get('orphan', 0)}")
                print(f"  TIME_WAIT sockets: {tcp_proto.get('tw', 0)}")
                print()

    if not analysis['issues'] and not analysis['warnings']:
        print("Status: OK - No socket buffer pressure detected")


def output_json(stats: Dict, config: Dict, analysis: Dict, page_size: int) -> None:
    """Output results in JSON format."""
    has_issues = len(analysis['issues']) > 0
    has_warnings = len(analysis['warnings']) > 0

    if has_issues:
        status = 'critical'
    elif has_warnings:
        status = 'warning'
    else:
        status = 'ok'

    result = {
        'timestamp': datetime.now().isoformat(),
        'status': status,
        'page_size_bytes': page_size,
        'issues': analysis['issues'],
        'warnings': analysis['warnings'],
        'protocols': analysis['protocols'],
        'config': {
            'rmem_default': config.get('rmem_default'),
            'rmem_max': config.get('rmem_max'),
            'wmem_default': config.get('wmem_default'),
            'wmem_max': config.get('wmem_max'),
            'tcp_mem': config.get('tcp_mem'),
            'tcp_rmem': config.get('tcp_rmem'),
            'tcp_wmem': config.get('tcp_wmem'),
            'udp_mem': config.get('udp_mem'),
        },
        'raw_stats': stats,
    }

    print(json.dumps(result, indent=2))


def output_table(stats: Dict, config: Dict, analysis: Dict,
                 page_size: int, warn_only: bool) -> None:
    """Output results in table format."""
    if warn_only and not analysis['issues'] and not analysis['warnings']:
        print("No socket buffer issues detected")
        return

    print(f"{'Protocol':<12} {'Sockets':<10} {'Memory':<12} {'Usage %':<10} {'Limit':<12} {'Status':<10}")
    print("=" * 66)

    for proto, data in analysis['protocols'].items():
        inuse = data.get('inuse', 0)
        mem_bytes = data.get('memory_bytes', data.get('memory_pages', 0) * page_size)
        usage_pct = data.get('usage_pct', 0)
        limit_bytes = data.get('limit_bytes', 0)

        mem_str = format_bytes(mem_bytes) if mem_bytes else '-'
        usage_str = f"{usage_pct:.1f}" if usage_pct else '-'
        limit_str = format_bytes(limit_bytes) if limit_bytes else '-'

        # Determine status
        status = 'OK'
        for issue in analysis['issues']:
            if issue['protocol'] == proto:
                status = 'CRITICAL'
                break
        if status == 'OK':
            for warning in analysis['warnings']:
                if warning['protocol'] == proto:
                    status = 'WARNING'
                    break

        print(f"{proto:<12} {inuse:<10} {mem_str:<12} {usage_str:<10} {limit_str:<12} {status:<10}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor socket buffer usage and memory pressure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        Show socket buffer status
  %(prog)s --format json          Output in JSON for monitoring
  %(prog)s --warn-only            Only show if issues detected
  %(prog)s --verbose              Show detailed buffer configuration
  %(prog)s --warn 70 --crit 85    Custom thresholds

Why socket buffer monitoring matters:
  When socket buffers are exhausted, the kernel will:
  - Drop incoming packets (receive buffer full)
  - Throttle or delay outgoing data (send buffer full)
  - Enter memory pressure mode (tcp_mem pressure threshold)

  High orphan or TIME_WAIT counts may indicate:
  - Connection leaks in applications
  - Need for tcp_tw_reuse tuning
  - DDoS or port scanning activity

Tuning hints:
  If TCP memory pressure detected:
    sysctl -w net.ipv4.tcp_mem="min pressure max"
  If buffer limits too small:
    sysctl -w net.core.rmem_max=16777216
    sysctl -w net.core.wmem_max=16777216
    sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

Exit codes:
  0 - No socket buffer pressure detected
  1 - Socket buffer pressure or warnings detected
  2 - Usage error or /proc filesystem unavailable
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
        help='Show detailed buffer configuration and statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )

    parser.add_argument(
        '--warn',
        type=float,
        default=70.0,
        metavar='PCT',
        help='Warning threshold percentage (default: 70)'
    )

    parser.add_argument(
        '--crit',
        type=float,
        default=85.0,
        metavar='PCT',
        help='Critical threshold percentage (default: 85)'
    )

    args = parser.parse_args()

    # Validate thresholds
    if args.warn < 0 or args.warn > 100:
        print("Error: --warn must be 0-100", file=sys.stderr)
        sys.exit(2)

    if args.crit < 0 or args.crit > 100:
        print("Error: --crit must be 0-100", file=sys.stderr)
        sys.exit(2)

    if args.warn >= args.crit:
        print("Error: --warn must be less than --crit", file=sys.stderr)
        sys.exit(2)

    # Check for /proc filesystem
    if not os.path.isdir('/proc'):
        print("Error: /proc filesystem not available", file=sys.stderr)
        print("This script requires a Linux system with procfs", file=sys.stderr)
        sys.exit(2)

    # Check for sockstat
    if not os.path.exists('/proc/net/sockstat'):
        print("Error: /proc/net/sockstat not available", file=sys.stderr)
        print("Socket statistics require a Linux kernel with network support", file=sys.stderr)
        sys.exit(2)

    # Collect data
    page_size = get_page_size()
    stats = get_socket_stats()
    config = get_buffer_config()

    # Analyze
    analysis = analyze_pressure(stats, config, page_size, args.warn, args.crit)

    # Output results
    if args.format == 'json':
        output_json(stats, config, analysis, page_size)
    elif args.format == 'table':
        output_table(stats, config, analysis, page_size, args.warn_only)
    else:
        output_plain(stats, config, analysis, page_size, args.verbose, args.warn_only)

    # Determine exit code
    if analysis['issues']:
        sys.exit(1)
    elif analysis['warnings']:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
