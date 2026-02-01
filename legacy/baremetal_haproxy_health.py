#!/usr/bin/env python3
"""
Baremetal HAProxy Health Monitor

Monitors HAProxy load balancer health via its stats socket or HTTP stats page.
Checks backend server health, session counts, error rates, and queue depths.

Useful for:
- Standalone HAProxy load balancers
- Database connection pooling (pgbouncer behind HAProxy)
- Web application load balancing
- API gateway health monitoring

Checks performed:
- Backend server health status (UP/DOWN/MAINT)
- Active session counts vs limits
- Request/error rates
- Queue depths and wait times
- Frontend/backend availability

Exit codes:
    0 - All backends healthy, no issues
    1 - Issues detected (backends down, high error rates, queue buildup)
    2 - Cannot connect to HAProxy stats or usage error

Examples:
    # Check via stats socket (default)
    baremetal_haproxy_health.py

    # Check via HTTP stats page
    baremetal_haproxy_health.py --url http://localhost:8404/stats

    # Check specific socket path
    baremetal_haproxy_health.py --socket /run/haproxy/admin.sock

    # JSON output for monitoring
    baremetal_haproxy_health.py --format json

    # Only show problems
    baremetal_haproxy_health.py --warn-only
"""

import argparse
import csv
import io
import json
import os
import socket
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from urllib.request import urlopen
from urllib.error import URLError


# Default paths and thresholds
DEFAULT_SOCKET_PATHS = [
    '/run/haproxy/admin.sock',
    '/var/run/haproxy/admin.sock',
    '/var/lib/haproxy/stats',
    '/run/haproxy.sock',
    '/var/run/haproxy.sock',
]

# Thresholds
DEFAULT_SESSION_WARN_PCT = 80   # Warn at 80% session limit
DEFAULT_SESSION_CRIT_PCT = 95  # Critical at 95% session limit
DEFAULT_ERROR_RATE_WARN = 1    # Warn at 1% error rate
DEFAULT_ERROR_RATE_CRIT = 5    # Critical at 5% error rate
DEFAULT_QUEUE_WARN = 10        # Warn when queue > 10
DEFAULT_QUEUE_CRIT = 50        # Critical when queue > 50


def find_haproxy_socket() -> Optional[str]:
    """Find the HAProxy stats socket."""
    for path in DEFAULT_SOCKET_PATHS:
        if os.path.exists(path):
            return path
    return None


def query_socket(socket_path: str, command: str = 'show stat\n',
                 timeout: int = 5) -> Tuple[bool, str]:
    """
    Query HAProxy via Unix socket.

    Args:
        socket_path: Path to HAProxy stats socket
        command: Command to send (default: show stat)
        timeout: Socket timeout in seconds

    Returns:
        Tuple of (success, response_data)
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(socket_path)
        sock.sendall(command.encode())

        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()
        return True, response.decode('utf-8', errors='replace')
    except socket.error as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def query_http(url: str, timeout: int = 10,
               username: Optional[str] = None,
               password: Optional[str] = None) -> Tuple[bool, str]:
    """
    Query HAProxy via HTTP stats page.

    Args:
        url: URL to HAProxy stats page (with ;csv suffix)
        timeout: HTTP timeout in seconds
        username: Optional HTTP basic auth username
        password: Optional HTTP basic auth password

    Returns:
        Tuple of (success, response_data)
    """
    # Ensure URL ends with ;csv for CSV output
    if not url.endswith(';csv'):
        url = url.rstrip('/') + ';csv'

    try:
        if username and password:
            # Add basic auth
            import base64
            credentials = base64.b64encode(
                f'{username}:{password}'.encode()
            ).decode('ascii')
            from urllib.request import Request
            req = Request(url)
            req.add_header('Authorization', f'Basic {credentials}')
            response = urlopen(req, timeout=timeout)
        else:
            response = urlopen(url, timeout=timeout)

        return True, response.read().decode('utf-8', errors='replace')
    except URLError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def parse_csv_stats(csv_data: str) -> List[Dict[str, Any]]:
    """
    Parse HAProxy CSV stats output.

    Args:
        csv_data: Raw CSV data from HAProxy stats

    Returns:
        List of dictionaries with parsed stats
    """
    stats = []

    # Remove leading # from header if present
    lines = csv_data.strip().split('\n')
    if lines and lines[0].startswith('# '):
        lines[0] = lines[0][2:]

    reader = csv.DictReader(io.StringIO('\n'.join(lines)))

    for row in reader:
        # Clean up keys (remove leading/trailing whitespace)
        cleaned = {k.strip(): v.strip() if v else '' for k, v in row.items()}
        stats.append(cleaned)

    return stats


def analyze_stats(stats: List[Dict[str, Any]],
                  session_warn_pct: int, session_crit_pct: int,
                  error_rate_warn: float, error_rate_crit: float,
                  queue_warn: int, queue_crit: int) -> Tuple[List[str], List[str], Dict]:
    """
    Analyze HAProxy stats and identify issues.

    Args:
        stats: Parsed stats data
        session_warn_pct: Session usage warning threshold (percent)
        session_crit_pct: Session usage critical threshold (percent)
        error_rate_warn: Error rate warning threshold (percent)
        error_rate_crit: Error rate critical threshold (percent)
        queue_warn: Queue depth warning threshold
        queue_crit: Queue depth critical threshold

    Returns:
        Tuple of (issues, warnings, analysis)
    """
    issues = []
    warnings = []
    analysis = {
        'healthy': True,
        'frontends': [],
        'backends': [],
        'servers': [],
        'total_sessions': 0,
        'total_requests': 0,
        'backends_up': 0,
        'backends_down': 0,
        'servers_up': 0,
        'servers_down': 0,
    }

    for entry in stats:
        pxname = entry.get('pxname', '')
        svname = entry.get('svname', '')
        status = entry.get('status', '')
        entry_type = entry.get('type', '')  # 0=frontend, 1=backend, 2=server

        # Skip empty entries
        if not pxname or not svname:
            continue

        # Parse numeric values safely
        def safe_int(val, default=0):
            try:
                return int(val) if val else default
            except (ValueError, TypeError):
                return default

        scur = safe_int(entry.get('scur'))  # Current sessions
        slim = safe_int(entry.get('slim'))  # Session limit
        qcur = safe_int(entry.get('qcur'))  # Current queue
        ereq = safe_int(entry.get('ereq'))  # Request errors
        econ = safe_int(entry.get('econ'))  # Connection errors
        eresp = safe_int(entry.get('eresp'))  # Response errors
        req_tot = safe_int(entry.get('req_tot'))  # Total requests
        hrsp_5xx = safe_int(entry.get('hrsp_5xx'))  # 5xx responses

        entry_info = {
            'name': f'{pxname}/{svname}',
            'status': status,
            'current_sessions': scur,
            'session_limit': slim,
            'queue': qcur,
            'errors': ereq + econ + eresp,
            'requests': req_tot,
            '5xx_responses': hrsp_5xx,
        }

        # Frontend analysis
        if svname == 'FRONTEND':
            analysis['frontends'].append(entry_info)
            analysis['total_requests'] += req_tot

            if status != 'OPEN':
                issues.append(f"Frontend {pxname} is {status}")

            # Session usage
            if slim > 0:
                session_pct = (scur / slim) * 100
                if session_pct >= session_crit_pct:
                    issues.append(
                        f"Frontend {pxname} session usage critical: "
                        f"{scur}/{slim} ({session_pct:.1f}%)"
                    )
                elif session_pct >= session_warn_pct:
                    warnings.append(
                        f"Frontend {pxname} session usage high: "
                        f"{scur}/{slim} ({session_pct:.1f}%)"
                    )

        # Backend analysis
        elif svname == 'BACKEND':
            analysis['backends'].append(entry_info)
            analysis['total_sessions'] += scur

            if status == 'UP':
                analysis['backends_up'] += 1
            else:
                analysis['backends_down'] += 1
                if status == 'DOWN':
                    issues.append(f"Backend {pxname} is DOWN")
                elif status == 'MAINT':
                    warnings.append(f"Backend {pxname} is in MAINT mode")
                else:
                    warnings.append(f"Backend {pxname} status: {status}")

            # Queue depth
            if qcur >= queue_crit:
                issues.append(f"Backend {pxname} queue critical: {qcur} requests")
            elif qcur >= queue_warn:
                warnings.append(f"Backend {pxname} queue high: {qcur} requests")

            # Error rate (if we have requests)
            if req_tot > 100:  # Only check if enough traffic
                total_errors = hrsp_5xx
                error_rate = (total_errors / req_tot) * 100
                if error_rate >= error_rate_crit:
                    issues.append(
                        f"Backend {pxname} error rate critical: "
                        f"{error_rate:.1f}% (5xx: {hrsp_5xx})"
                    )
                elif error_rate >= error_rate_warn:
                    warnings.append(
                        f"Backend {pxname} error rate high: "
                        f"{error_rate:.1f}% (5xx: {hrsp_5xx})"
                    )

        # Server analysis
        else:
            analysis['servers'].append(entry_info)

            if status in ('UP', 'no check'):
                analysis['servers_up'] += 1
            else:
                analysis['servers_down'] += 1
                if status == 'DOWN':
                    issues.append(f"Server {pxname}/{svname} is DOWN")
                elif status == 'MAINT':
                    warnings.append(f"Server {pxname}/{svname} is in MAINT mode")
                elif status == 'DRAIN':
                    warnings.append(f"Server {pxname}/{svname} is DRAINing")
                elif status != 'no check':
                    warnings.append(f"Server {pxname}/{svname} status: {status}")

    # Set overall health
    analysis['healthy'] = len(issues) == 0

    return issues, warnings, analysis


def format_plain(stats: List[Dict], issues: List[str], warnings: List[str],
                 analysis: Dict, verbose: bool = False) -> str:
    """Format output as plain text."""
    lines = []
    lines.append("HAProxy Health Monitor")
    lines.append("=" * 50)
    lines.append("")

    # Summary
    status_str = "HEALTHY" if analysis['healthy'] else "UNHEALTHY"
    lines.append(f"Status: {status_str}")
    lines.append(f"Backends: {analysis['backends_up']} up, {analysis['backends_down']} down")
    lines.append(f"Servers: {analysis['servers_up']} up, {analysis['servers_down']} down")
    lines.append(f"Active Sessions: {analysis['total_sessions']}")
    lines.append(f"Total Requests: {analysis['total_requests']}")
    lines.append("")

    # Frontends
    if verbose and analysis['frontends']:
        lines.append("Frontends:")
        for fe in analysis['frontends']:
            status_mark = "OK" if fe['status'] == 'OPEN' else fe['status']
            lines.append(f"  {fe['name']}: {status_mark} "
                        f"(sessions: {fe['current_sessions']}/{fe['session_limit']})")
        lines.append("")

    # Backends
    if verbose and analysis['backends']:
        lines.append("Backends:")
        for be in analysis['backends']:
            status_mark = "UP" if be['status'] == 'UP' else be['status']
            lines.append(f"  {be['name']}: {status_mark} "
                        f"(sessions: {be['current_sessions']}, queue: {be['queue']})")
        lines.append("")

    # Servers (only if verbose)
    if verbose and analysis['servers']:
        lines.append("Servers:")
        for srv in analysis['servers']:
            status_mark = "UP" if srv['status'] in ('UP', 'no check') else srv['status']
            lines.append(f"  {srv['name']}: {status_mark} "
                        f"(sessions: {srv['current_sessions']})")
        lines.append("")

    # Issues
    if issues:
        lines.append("ISSUES:")
        for issue in issues:
            lines.append(f"  [!] {issue}")
        lines.append("")

    if warnings:
        lines.append("WARNINGS:")
        for warning in warnings:
            lines.append(f"  [*] {warning}")
        lines.append("")

    if not issues and not warnings:
        lines.append("[OK] HAProxy is healthy")

    return '\n'.join(lines)


def format_json(stats: List[Dict], issues: List[str], warnings: List[str],
                analysis: Dict) -> str:
    """Format output as JSON."""
    output = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'healthy': analysis['healthy'],
        'summary': {
            'backends_up': analysis['backends_up'],
            'backends_down': analysis['backends_down'],
            'servers_up': analysis['servers_up'],
            'servers_down': analysis['servers_down'],
            'total_sessions': analysis['total_sessions'],
            'total_requests': analysis['total_requests'],
        },
        'frontends': analysis['frontends'],
        'backends': analysis['backends'],
        'servers': analysis['servers'],
        'issues': issues,
        'warnings': warnings,
    }
    return json.dumps(output, indent=2)


def format_table(stats: List[Dict], issues: List[str], warnings: List[str],
                 analysis: Dict) -> str:
    """Format output as a table."""
    lines = []

    # Header
    lines.append(f"{'METRIC':<25} {'VALUE':<20} {'STATUS':<15}")
    lines.append("-" * 60)

    # Metrics
    health_status = "OK" if analysis['healthy'] else "CRITICAL"
    lines.append(f"{'Overall Health':<25} {'':<20} {health_status:<15}")

    backends_str = f"{analysis['backends_up']}/{analysis['backends_up'] + analysis['backends_down']}"
    backends_status = "OK" if analysis['backends_down'] == 0 else "DEGRADED"
    lines.append(f"{'Backends Up':<25} {backends_str:<20} {backends_status:<15}")

    servers_str = f"{analysis['servers_up']}/{analysis['servers_up'] + analysis['servers_down']}"
    servers_status = "OK" if analysis['servers_down'] == 0 else "DEGRADED"
    lines.append(f"{'Servers Up':<25} {servers_str:<20} {servers_status:<15}")

    lines.append(f"{'Active Sessions':<25} {analysis['total_sessions']:<20} {'':<15}")
    lines.append(f"{'Total Requests':<25} {analysis['total_requests']:<20} {'':<15}")

    lines.append("-" * 60)

    # Issues summary
    if issues:
        lines.append("Issues:")
        for issue in issues[:5]:
            lines.append(f"  [!] {issue[:55]}")

    if warnings:
        lines.append("Warnings:")
        for warning in warnings[:5]:
            lines.append(f"  [*] {warning[:55]}")

    if not issues and not warnings:
        lines.append("Status: All checks passed")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor HAProxy health via stats socket or HTTP',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # Auto-detect socket
  %(prog)s --socket /run/haproxy/admin.sock   # Specific socket
  %(prog)s --url http://localhost:8404/stats  # HTTP stats page
  %(prog)s --format json                      # JSON output
  %(prog)s --warn-only                        # Only show problems
  %(prog)s -v                                 # Verbose output

Exit codes:
  0 - All healthy
  1 - Issues detected
  2 - Cannot connect or usage error
        """
    )

    # Connection options
    conn_group = parser.add_mutually_exclusive_group()
    conn_group.add_argument(
        '-s', '--socket',
        help='Path to HAProxy stats socket'
    )
    conn_group.add_argument(
        '-u', '--url',
        help='URL to HAProxy HTTP stats page'
    )

    # HTTP auth options
    parser.add_argument(
        '--username',
        help='Username for HTTP basic auth'
    )
    parser.add_argument(
        '--password',
        help='Password for HTTP basic auth'
    )

    # Output options
    parser.add_argument(
        '-f', '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show output if issues or warnings detected'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    # Threshold options
    parser.add_argument(
        '--session-warn-pct',
        type=int,
        default=DEFAULT_SESSION_WARN_PCT,
        help=f'Session usage warning threshold %% (default: {DEFAULT_SESSION_WARN_PCT})'
    )
    parser.add_argument(
        '--session-crit-pct',
        type=int,
        default=DEFAULT_SESSION_CRIT_PCT,
        help=f'Session usage critical threshold %% (default: {DEFAULT_SESSION_CRIT_PCT})'
    )
    parser.add_argument(
        '--error-rate-warn',
        type=float,
        default=DEFAULT_ERROR_RATE_WARN,
        help=f'Error rate warning threshold %% (default: {DEFAULT_ERROR_RATE_WARN})'
    )
    parser.add_argument(
        '--error-rate-crit',
        type=float,
        default=DEFAULT_ERROR_RATE_CRIT,
        help=f'Error rate critical threshold %% (default: {DEFAULT_ERROR_RATE_CRIT})'
    )
    parser.add_argument(
        '--queue-warn',
        type=int,
        default=DEFAULT_QUEUE_WARN,
        help=f'Queue depth warning threshold (default: {DEFAULT_QUEUE_WARN})'
    )
    parser.add_argument(
        '--queue-crit',
        type=int,
        default=DEFAULT_QUEUE_CRIT,
        help=f'Queue depth critical threshold (default: {DEFAULT_QUEUE_CRIT})'
    )

    args = parser.parse_args()

    # Determine connection method
    if args.url:
        # Use HTTP
        success, data = query_http(
            args.url, username=args.username, password=args.password
        )
        if not success:
            print(f"Error: Cannot connect to HAProxy HTTP stats: {data}",
                  file=sys.stderr)
            sys.exit(2)
    else:
        # Use socket
        socket_path = args.socket or find_haproxy_socket()
        if not socket_path:
            print("Error: HAProxy stats socket not found", file=sys.stderr)
            print("Tried: " + ', '.join(DEFAULT_SOCKET_PATHS), file=sys.stderr)
            print("Use --socket to specify path or --url for HTTP stats",
                  file=sys.stderr)
            sys.exit(2)

        if not os.path.exists(socket_path):
            print(f"Error: Socket not found: {socket_path}", file=sys.stderr)
            sys.exit(2)

        success, data = query_socket(socket_path)
        if not success:
            print(f"Error: Cannot connect to HAProxy socket: {data}",
                  file=sys.stderr)
            sys.exit(2)

    # Parse stats
    try:
        stats = parse_csv_stats(data)
    except Exception as e:
        print(f"Error: Failed to parse HAProxy stats: {e}", file=sys.stderr)
        sys.exit(2)

    if not stats:
        print("Error: No stats data received from HAProxy", file=sys.stderr)
        sys.exit(2)

    # Analyze stats
    issues, warnings, analysis = analyze_stats(
        stats,
        args.session_warn_pct, args.session_crit_pct,
        args.error_rate_warn, args.error_rate_crit,
        args.queue_warn, args.queue_crit
    )

    # Format output
    if args.format == 'json':
        output = format_json(stats, issues, warnings, analysis)
    elif args.format == 'table':
        output = format_table(stats, issues, warnings, analysis)
    else:
        output = format_plain(stats, issues, warnings, analysis, args.verbose)

    # Print output (respecting --warn-only)
    if not args.warn_only or issues or warnings:
        print(output)

    # Return appropriate exit code
    sys.exit(1 if issues else 0)


if __name__ == '__main__':
    main()
