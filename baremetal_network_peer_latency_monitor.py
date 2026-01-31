#!/usr/bin/env python3
"""
Monitor network latency to configured peers and gateways.

Measures round-trip time (RTT) to specified network targets using ICMP ping
or TCP connect probes. Useful for detecting network degradation, high latency
paths, or connectivity issues in large-scale baremetal environments.

Features:
- ICMP ping-based latency measurement
- TCP connect latency as alternative (for environments blocking ICMP)
- Multiple target monitoring with configurable thresholds
- Statistical analysis (min/avg/max/stddev)
- Automatic default gateway detection

Exit codes:
    0 - All targets reachable with acceptable latency
    1 - Latency warnings or unreachable targets detected
    2 - Usage error or missing dependencies

Examples:
    # Monitor latency to default gateway
    baremetal_network_peer_latency_monitor.py

    # Monitor specific targets
    baremetal_network_peer_latency_monitor.py --targets 8.8.8.8,1.1.1.1

    # Set latency thresholds
    baremetal_network_peer_latency_monitor.py --warn-ms 50 --crit-ms 100

    # Use TCP probe instead of ICMP
    baremetal_network_peer_latency_monitor.py --tcp --port 443 --targets google.com

    # JSON output
    baremetal_network_peer_latency_monitor.py --format json
"""

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from typing import Dict, List, Any, Optional


def run_command(cmd: List[str]) -> tuple:
    """
    Execute a command and return (returncode, stdout, stderr).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except Exception as e:
        return -1, "", str(e)


def check_ping_available() -> bool:
    """Check if ping command is available."""
    returncode, _, _ = run_command(['ping', '-c', '1', '-W', '1', '127.0.0.1'])
    return returncode == 0


def get_default_gateway() -> Optional[str]:
    """Get the default gateway IP address."""
    returncode, stdout, _ = run_command(['ip', 'route', 'show', 'default'])
    if returncode != 0:
        return None

    # Parse "default via X.X.X.X dev ethX"
    match = re.search(r'default via ([\d.]+)', stdout)
    if match:
        return match.group(1)

    return None


def ping_target(target: str, count: int = 5, timeout: int = 2) -> Dict[str, Any]:
    """
    Ping a target and return latency statistics.

    Args:
        target: IP address or hostname to ping
        count: Number of ping packets to send
        timeout: Timeout per packet in seconds

    Returns:
        Dictionary with ping results
    """
    result = {
        'target': target,
        'reachable': False,
        'method': 'icmp',
        'packets_sent': count,
        'packets_received': 0,
        'packet_loss_pct': 100.0,
        'min_ms': None,
        'avg_ms': None,
        'max_ms': None,
        'stddev_ms': None,
        'error': None
    }

    cmd = ['ping', '-c', str(count), '-W', str(timeout), target]
    returncode, stdout, stderr = run_command(cmd)

    if returncode == -1:
        result['error'] = stderr
        return result

    # Parse packet statistics
    # "X packets transmitted, Y received, Z% packet loss"
    stats_match = re.search(
        r'(\d+) packets transmitted, (\d+) (?:packets )?received',
        stdout
    )
    if stats_match:
        result['packets_sent'] = int(stats_match.group(1))
        result['packets_received'] = int(stats_match.group(2))
        if result['packets_sent'] > 0:
            result['packet_loss_pct'] = (
                (result['packets_sent'] - result['packets_received']) /
                result['packets_sent'] * 100
            )

    # Parse RTT statistics
    # "rtt min/avg/max/mdev = X.XXX/Y.YYY/Z.ZZZ/W.WWW ms"
    rtt_match = re.search(
        r'(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = '
        r'([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)',
        stdout
    )
    if rtt_match:
        result['min_ms'] = float(rtt_match.group(1))
        result['avg_ms'] = float(rtt_match.group(2))
        result['max_ms'] = float(rtt_match.group(3))
        result['stddev_ms'] = float(rtt_match.group(4))
        result['reachable'] = True
    elif result['packets_received'] > 0:
        result['reachable'] = True

    return result


def tcp_probe_target(target: str, port: int = 443,
                     count: int = 5, timeout: int = 2) -> Dict[str, Any]:
    """
    Measure TCP connect latency to a target.

    Args:
        target: IP address or hostname
        port: TCP port to connect to
        count: Number of connection attempts
        timeout: Timeout per connection in seconds

    Returns:
        Dictionary with probe results
    """
    result = {
        'target': target,
        'port': port,
        'reachable': False,
        'method': 'tcp',
        'attempts': count,
        'successful': 0,
        'failure_rate_pct': 100.0,
        'min_ms': None,
        'avg_ms': None,
        'max_ms': None,
        'latencies': [],
        'error': None
    }

    latencies = []

    for _ in range(count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            start_time = time.perf_counter()
            sock.connect((target, port))
            end_time = time.perf_counter()

            latency_ms = (end_time - start_time) * 1000
            latencies.append(latency_ms)
            result['successful'] += 1

            sock.close()

        except socket.timeout:
            pass
        except socket.gaierror as e:
            result['error'] = f"DNS resolution failed: {e}"
            break
        except socket.error as e:
            # Connection refused is still "reachable" - just closed port
            if e.errno == 111:  # Connection refused
                # Measure time to refusal
                pass
            result['error'] = str(e)
        except Exception as e:
            result['error'] = str(e)

    if latencies:
        result['latencies'] = latencies
        result['min_ms'] = min(latencies)
        result['max_ms'] = max(latencies)
        result['avg_ms'] = sum(latencies) / len(latencies)
        result['reachable'] = True

    if result['attempts'] > 0:
        result['failure_rate_pct'] = (
            (result['attempts'] - result['successful']) /
            result['attempts'] * 100
        )

    return result


def analyze_results(results: List[Dict[str, Any]], warn_ms: float,
                    crit_ms: float, max_loss_pct: float) -> List[Dict[str, Any]]:
    """
    Analyze results and add status based on thresholds.

    Args:
        results: List of probe results
        warn_ms: Warning threshold for average latency
        crit_ms: Critical threshold for average latency
        max_loss_pct: Maximum acceptable packet loss percentage

    Returns:
        Results with added 'status' and 'issues' fields
    """
    for result in results:
        result['status'] = 'ok'
        result['issues'] = []

        if not result['reachable']:
            result['status'] = 'critical'
            result['issues'].append('unreachable')
            continue

        avg_ms = result.get('avg_ms')
        if avg_ms is not None:
            if avg_ms >= crit_ms:
                result['status'] = 'critical'
                result['issues'].append(f'latency {avg_ms:.1f}ms >= {crit_ms}ms')
            elif avg_ms >= warn_ms:
                result['status'] = 'warning'
                result['issues'].append(f'latency {avg_ms:.1f}ms >= {warn_ms}ms')

        loss_pct = result.get('packet_loss_pct', result.get('failure_rate_pct', 0))
        if loss_pct > max_loss_pct:
            if result['status'] != 'critical':
                result['status'] = 'warning'
            result['issues'].append(f'packet loss {loss_pct:.1f}% > {max_loss_pct}%')

    return results


def format_plain_output(results: List[Dict[str, Any]], verbose: bool = False,
                        warn_only: bool = False) -> str:
    """Format output as plain text."""
    lines = []

    # Summary counts
    ok_count = sum(1 for r in results if r['status'] == 'ok')
    warn_count = sum(1 for r in results if r['status'] == 'warning')
    crit_count = sum(1 for r in results if r['status'] == 'critical')

    if not warn_only:
        lines.append("Network Peer Latency Monitor")
        lines.append("=" * 60)
        lines.append(f"Targets checked: {len(results)}")
        lines.append(f"OK: {ok_count} | Warnings: {warn_count} | Critical: {crit_count}")
        lines.append("")

    for result in results:
        if warn_only and result['status'] == 'ok':
            continue

        target = result['target']
        method = result['method']

        if result['status'] == 'critical':
            symbol = "[CRIT]"
        elif result['status'] == 'warning':
            symbol = "[WARN]"
        else:
            symbol = "[OK]  "

        if result['reachable']:
            avg_ms = result.get('avg_ms', 0)
            min_ms = result.get('min_ms', 0)
            max_ms = result.get('max_ms', 0)

            if method == 'tcp':
                port = result.get('port', '')
                lines.append(
                    f"{symbol} {target}:{port} - "
                    f"avg={avg_ms:.1f}ms min={min_ms:.1f}ms max={max_ms:.1f}ms"
                )
            else:
                loss_pct = result.get('packet_loss_pct', 0)
                lines.append(
                    f"{symbol} {target} - "
                    f"avg={avg_ms:.1f}ms min={min_ms:.1f}ms max={max_ms:.1f}ms "
                    f"loss={loss_pct:.0f}%"
                )
        else:
            error = result.get('error', 'unreachable')
            lines.append(f"{symbol} {target} - UNREACHABLE ({error})")

        if verbose and result['issues']:
            for issue in result['issues']:
                lines.append(f"       Issue: {issue}")

    if not results:
        lines.append("No targets configured")

    return '\n'.join(lines)


def format_json_output(results: List[Dict[str, Any]]) -> str:
    """Format output as JSON."""
    ok_count = sum(1 for r in results if r['status'] == 'ok')
    warn_count = sum(1 for r in results if r['status'] == 'warning')
    crit_count = sum(1 for r in results if r['status'] == 'critical')

    output = {
        'summary': {
            'total_targets': len(results),
            'ok': ok_count,
            'warning': warn_count,
            'critical': crit_count,
            'has_issues': (warn_count + crit_count) > 0
        },
        'results': results
    }

    # Remove internal latencies list for cleaner output
    for r in output['results']:
        r.pop('latencies', None)

    return json.dumps(output, indent=2)


def format_table_output(results: List[Dict[str, Any]],
                        warn_only: bool = False) -> str:
    """Format output as a table."""
    lines = []

    header = f"{'STATUS':<8} {'TARGET':<30} {'AVG(ms)':<10} {'MIN(ms)':<10} {'MAX(ms)':<10} {'LOSS%':<8}"
    lines.append(header)
    lines.append("-" * 80)

    for result in results:
        if warn_only and result['status'] == 'ok':
            continue

        status = result['status'].upper()
        target = result['target'][:28]
        if result['method'] == 'tcp':
            target = f"{target}:{result.get('port', '')}"[:28]

        if result['reachable']:
            avg_ms = f"{result.get('avg_ms', 0):.1f}"
            min_ms = f"{result.get('min_ms', 0):.1f}"
            max_ms = f"{result.get('max_ms', 0):.1f}"
            loss = result.get('packet_loss_pct', result.get('failure_rate_pct', 0))
            loss_str = f"{loss:.0f}%"
        else:
            avg_ms = min_ms = max_ms = "-"
            loss_str = "100%"

        lines.append(
            f"{status:<8} {target:<30} {avg_ms:<10} {min_ms:<10} {max_ms:<10} {loss_str:<8}"
        )

    lines.append("-" * 80)

    ok_count = sum(1 for r in results if r['status'] == 'ok')
    warn_count = sum(1 for r in results if r['status'] == 'warning')
    crit_count = sum(1 for r in results if r['status'] == 'critical')
    lines.append(f"Total: {len(results)} | OK: {ok_count} | Warn: {warn_count} | Crit: {crit_count}")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor network latency to peers and gateways',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Monitor default gateway
  %(prog)s --targets 8.8.8.8,1.1.1.1   # Monitor specific targets
  %(prog)s --warn-ms 50 --crit-ms 100  # Custom thresholds
  %(prog)s --tcp --port 443            # Use TCP probes
  %(prog)s --format json               # JSON output
  %(prog)s --count 10                  # More samples for accuracy

Thresholds:
  --warn-ms: Average latency warning threshold (default: 50ms)
  --crit-ms: Average latency critical threshold (default: 100ms)
  --max-loss: Maximum acceptable packet loss (default: 10%%)

Exit codes:
  0 - All targets OK
  1 - Warnings or critical issues
  2 - Usage error or missing dependencies
"""
    )

    parser.add_argument(
        '-t', '--targets',
        help='Comma-separated list of targets (IP/hostname). Default: gateway'
    )
    parser.add_argument(
        '-c', '--count',
        type=int,
        default=5,
        help='Number of probes per target (default: 5)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=2,
        help='Timeout per probe in seconds (default: 2)'
    )
    parser.add_argument(
        '--tcp',
        action='store_true',
        help='Use TCP connect probes instead of ICMP'
    )
    parser.add_argument(
        '-p', '--port',
        type=int,
        default=443,
        help='TCP port for --tcp mode (default: 443)'
    )
    parser.add_argument(
        '--warn-ms',
        type=float,
        default=50.0,
        help='Warning threshold for avg latency in ms (default: 50)'
    )
    parser.add_argument(
        '--crit-ms',
        type=float,
        default=100.0,
        help='Critical threshold for avg latency in ms (default: 100)'
    )
    parser.add_argument(
        '--max-loss',
        type=float,
        default=10.0,
        help='Maximum acceptable packet loss %% (default: 10)'
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
        help='Show detailed information'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show targets with issues'
    )

    args = parser.parse_args()

    # Determine targets
    targets = []
    if args.targets:
        targets = [t.strip() for t in args.targets.split(',') if t.strip()]
    else:
        # Default to gateway
        gateway = get_default_gateway()
        if gateway:
            targets = [gateway]
        else:
            print("Error: No default gateway found and no targets specified",
                  file=sys.stderr)
            print("Use --targets to specify targets", file=sys.stderr)
            sys.exit(2)

    # Check dependencies for ICMP mode
    if not args.tcp and not check_ping_available():
        print("Error: ping command not available", file=sys.stderr)
        print("Use --tcp for TCP-based probes instead", file=sys.stderr)
        sys.exit(2)

    # Probe all targets
    results = []
    for target in targets:
        if args.tcp:
            result = tcp_probe_target(
                target,
                port=args.port,
                count=args.count,
                timeout=args.timeout
            )
        else:
            result = ping_target(
                target,
                count=args.count,
                timeout=args.timeout
            )
        results.append(result)

    # Analyze results against thresholds
    results = analyze_results(
        results,
        warn_ms=args.warn_ms,
        crit_ms=args.crit_ms,
        max_loss_pct=args.max_loss
    )

    # Format and print output
    if args.format == 'json':
        print(format_json_output(results))
    elif args.format == 'table':
        print(format_table_output(results, warn_only=args.warn_only))
    else:
        print(format_plain_output(results, verbose=args.verbose,
                                  warn_only=args.warn_only))

    # Determine exit code
    has_critical = any(r['status'] == 'critical' for r in results)
    has_warning = any(r['status'] == 'warning' for r in results)

    if has_critical or has_warning:
        sys.exit(1)
    sys.exit(0)


if __name__ == '__main__':
    main()
