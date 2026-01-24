#!/usr/bin/env python3
"""
Monitor DNS resolver configuration and health on baremetal systems.

Checks /etc/resolv.conf configuration, validates nameserver reachability,
tests DNS resolution, and monitors systemd-resolved status if present.
Critical for large-scale environments where DNS issues cause cascading failures.

Exit codes:
    0 - All resolvers healthy and reachable
    1 - DNS issues detected (unreachable resolvers, resolution failures)
    2 - Usage error or missing dependency
"""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time


def read_resolv_conf(path='/etc/resolv.conf'):
    """Parse /etc/resolv.conf and extract configuration."""
    config = {
        'nameservers': [],
        'search_domains': [],
        'options': [],
        'path': path,
        'exists': False,
        'readable': False
    }

    if not os.path.exists(path):
        return config

    config['exists'] = True

    try:
        with open(path, 'r') as f:
            content = f.read()
        config['readable'] = True
    except PermissionError:
        return config
    except Exception:
        return config

    for line in content.split('\n'):
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith('#'):
            continue

        # Parse nameserver entries
        if line.startswith('nameserver'):
            parts = line.split()
            if len(parts) >= 2:
                config['nameservers'].append(parts[1])

        # Parse search domains
        elif line.startswith('search') or line.startswith('domain'):
            parts = line.split()
            if len(parts) >= 2:
                config['search_domains'].extend(parts[1:])

        # Parse options
        elif line.startswith('options'):
            parts = line.split()
            if len(parts) >= 2:
                config['options'].extend(parts[1:])

    return config


def check_systemd_resolved():
    """Check if systemd-resolved is running and get its status."""
    status = {
        'running': False,
        'listening': False,
        'dns_servers': [],
        'current_dns': [],
        'dnssec': None,
        'cache_statistics': None
    }

    # Check if systemd-resolved is active
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'systemd-resolved'],
            capture_output=True,
            text=True
        )
        status['running'] = result.returncode == 0
    except FileNotFoundError:
        return None  # systemd not available

    if not status['running']:
        return status

    # Check if resolved is listening on 127.0.0.53
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.connect(('127.0.0.53', 53))
        sock.close()
        status['listening'] = True
    except Exception:
        status['listening'] = False

    # Get DNS server information from resolvectl
    try:
        result = subprocess.run(
            ['resolvectl', 'status'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            # Parse DNS servers
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'DNS Servers:' in line or 'Current DNS Server:' in line:
                    match = re.search(r':\s*(.+)', line)
                    if match:
                        servers = match.group(1).split()
                        if 'Current' in line:
                            status['current_dns'] = servers
                        else:
                            status['dns_servers'].extend(servers)
                elif 'DNSSEC' in line:
                    match = re.search(r':\s*(.+)', line)
                    if match:
                        status['dnssec'] = match.group(1).strip()
    except FileNotFoundError:
        pass

    # Get cache statistics if available
    try:
        result = subprocess.run(
            ['resolvectl', 'statistics'],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            stats = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower().replace(' ', '_')
                    value = value.strip()
                    if value.isdigit():
                        stats[key] = int(value)
                    else:
                        stats[key] = value
            if stats:
                status['cache_statistics'] = stats
    except FileNotFoundError:
        pass

    return status


def test_nameserver_reachability(nameserver, timeout=2):
    """Test if a nameserver is reachable via DNS query."""
    result = {
        'nameserver': nameserver,
        'reachable': False,
        'latency_ms': None,
        'error': None
    }

    # Try to resolve a well-known domain
    try:
        start_time = time.time()

        # Use socket to test UDP connectivity to port 53
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Simple DNS query for 'google.com' A record
        # DNS header + question for google.com
        query = (
            b'\x12\x34'  # Transaction ID
            b'\x01\x00'  # Flags: standard query
            b'\x00\x01'  # Questions: 1
            b'\x00\x00'  # Answers: 0
            b'\x00\x00'  # Authority: 0
            b'\x00\x00'  # Additional: 0
            b'\x06google\x03com\x00'  # QNAME: google.com
            b'\x00\x01'  # QTYPE: A
            b'\x00\x01'  # QCLASS: IN
        )

        sock.sendto(query, (nameserver, 53))
        response, _ = sock.recvfrom(512)
        sock.close()

        end_time = time.time()
        result['latency_ms'] = (end_time - start_time) * 1000
        result['reachable'] = len(response) > 12  # Minimum DNS response size

    except socket.timeout:
        result['error'] = 'timeout'
    except socket.gaierror as e:
        result['error'] = f'address error: {e}'
    except Exception as e:
        result['error'] = str(e)

    return result


def test_dns_resolution(domain, expected_ip=None, timeout=5):
    """Test DNS resolution for a specific domain."""
    result = {
        'domain': domain,
        'resolved': False,
        'addresses': [],
        'latency_ms': None,
        'error': None,
        'expected_match': None
    }

    try:
        start_time = time.time()
        socket.setdefaulttimeout(timeout)
        addresses = socket.gethostbyname_ex(domain)
        end_time = time.time()

        result['resolved'] = True
        result['addresses'] = addresses[2]  # IP addresses
        result['latency_ms'] = (end_time - start_time) * 1000

        if expected_ip:
            result['expected_match'] = expected_ip in addresses[2]

    except socket.gaierror as e:
        result['error'] = str(e)
    except socket.timeout:
        result['error'] = 'timeout'
    except Exception as e:
        result['error'] = str(e)

    return result


def test_reverse_dns(ip_address, timeout=5):
    """Test reverse DNS resolution for an IP address."""
    result = {
        'ip_address': ip_address,
        'resolved': False,
        'hostname': None,
        'latency_ms': None,
        'error': None
    }

    try:
        start_time = time.time()
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        end_time = time.time()

        result['resolved'] = True
        result['hostname'] = hostname
        result['latency_ms'] = (end_time - start_time) * 1000

    except socket.herror as e:
        result['error'] = str(e)
    except socket.timeout:
        result['error'] = 'timeout'
    except Exception as e:
        result['error'] = str(e)

    return result


def analyze_dns_health(resolv_conf, resolved_status, nameserver_results,
                       resolution_tests):
    """Analyze overall DNS health and return issues."""
    issues = []
    warnings = []

    # Check resolv.conf exists and is readable
    if not resolv_conf['exists']:
        issues.append({
            'severity': 'critical',
            'type': 'missing_resolv_conf',
            'message': '/etc/resolv.conf does not exist'
        })
    elif not resolv_conf['readable']:
        issues.append({
            'severity': 'critical',
            'type': 'unreadable_resolv_conf',
            'message': '/etc/resolv.conf is not readable'
        })

    # Check for nameservers
    if resolv_conf['exists'] and not resolv_conf['nameservers']:
        issues.append({
            'severity': 'critical',
            'type': 'no_nameservers',
            'message': 'No nameservers configured in /etc/resolv.conf'
        })

    # Check nameserver reachability
    unreachable_count = 0
    for ns_result in nameserver_results:
        if not ns_result['reachable']:
            unreachable_count += 1
            issues.append({
                'severity': 'warning' if unreachable_count < len(nameserver_results) else 'critical',
                'type': 'nameserver_unreachable',
                'message': f"Nameserver {ns_result['nameserver']} is unreachable: {ns_result['error']}",
                'nameserver': ns_result['nameserver']
            })
        elif ns_result['latency_ms'] and ns_result['latency_ms'] > 500:
            warnings.append({
                'severity': 'warning',
                'type': 'nameserver_slow',
                'message': f"Nameserver {ns_result['nameserver']} has high latency ({ns_result['latency_ms']:.0f}ms)",
                'nameserver': ns_result['nameserver'],
                'latency_ms': ns_result['latency_ms']
            })

    # Check if all nameservers are unreachable
    if unreachable_count == len(nameserver_results) and nameserver_results:
        # Upgrade to critical
        for issue in issues:
            if issue['type'] == 'nameserver_unreachable':
                issue['severity'] = 'critical'

    # Check resolution tests
    for res_test in resolution_tests:
        if not res_test['resolved']:
            issues.append({
                'severity': 'critical',
                'type': 'resolution_failure',
                'message': f"Failed to resolve {res_test['domain']}: {res_test['error']}",
                'domain': res_test['domain']
            })
        elif res_test.get('expected_match') is False:
            warnings.append({
                'severity': 'warning',
                'type': 'resolution_mismatch',
                'message': f"Resolution for {res_test['domain']} did not match expected IP",
                'domain': res_test['domain']
            })

    # Check systemd-resolved status
    if resolved_status:
        if resolved_status['running'] and not resolved_status['listening']:
            warnings.append({
                'severity': 'warning',
                'type': 'resolved_not_listening',
                'message': 'systemd-resolved is running but not listening on 127.0.0.53'
            })

    # Check for loopback-only configuration
    if resolv_conf['nameservers']:
        all_loopback = all(
            ns.startswith('127.') or ns == '::1'
            for ns in resolv_conf['nameservers']
        )
        if all_loopback and not (resolved_status and resolved_status['running']):
            warnings.append({
                'severity': 'warning',
                'type': 'loopback_only_no_resolver',
                'message': 'Only loopback nameservers configured but no local resolver running'
            })

    return issues, warnings


def format_plain(resolv_conf, resolved_status, nameserver_results,
                 resolution_tests, issues, warnings, verbose=False):
    """Format DNS health data as plain text."""
    output = []

    output.append("DNS Resolver Health Monitor")
    output.append("=" * 60)
    output.append("")

    # resolv.conf status
    output.append("Configuration (/etc/resolv.conf):")
    output.append("-" * 40)

    if not resolv_conf['exists']:
        output.append("  [CRITICAL] File does not exist!")
    elif not resolv_conf['readable']:
        output.append("  [CRITICAL] File is not readable!")
    else:
        if resolv_conf['nameservers']:
            output.append(f"  Nameservers: {', '.join(resolv_conf['nameservers'])}")
        else:
            output.append("  Nameservers: None configured [CRITICAL]")

        if resolv_conf['search_domains']:
            output.append(f"  Search domains: {', '.join(resolv_conf['search_domains'])}")

        if verbose and resolv_conf['options']:
            output.append(f"  Options: {', '.join(resolv_conf['options'])}")

    output.append("")

    # Nameserver reachability
    if nameserver_results:
        output.append("Nameserver Reachability:")
        output.append("-" * 40)

        for ns_result in nameserver_results:
            if ns_result['reachable']:
                latency = f" ({ns_result['latency_ms']:.0f}ms)" if ns_result['latency_ms'] else ""
                output.append(f"  [OK] {ns_result['nameserver']}{latency}")
            else:
                output.append(f"  [FAIL] {ns_result['nameserver']}: {ns_result['error']}")

        output.append("")

    # Resolution tests
    if resolution_tests:
        output.append("DNS Resolution Tests:")
        output.append("-" * 40)

        for res_test in resolution_tests:
            if res_test['resolved']:
                ips = ', '.join(res_test['addresses'][:3])
                if len(res_test['addresses']) > 3:
                    ips += f" (+{len(res_test['addresses']) - 3} more)"
                latency = f" ({res_test['latency_ms']:.0f}ms)" if res_test['latency_ms'] else ""
                output.append(f"  [OK] {res_test['domain']} -> {ips}{latency}")
            else:
                output.append(f"  [FAIL] {res_test['domain']}: {res_test['error']}")

        output.append("")

    # systemd-resolved status
    if resolved_status is not None and verbose:
        output.append("systemd-resolved Status:")
        output.append("-" * 40)

        status = "Running" if resolved_status['running'] else "Not running"
        output.append(f"  Status: {status}")

        if resolved_status['running']:
            listening = "Yes" if resolved_status['listening'] else "No"
            output.append(f"  Listening on 127.0.0.53: {listening}")

            if resolved_status['current_dns']:
                output.append(f"  Current DNS: {', '.join(resolved_status['current_dns'])}")

            if resolved_status['dnssec']:
                output.append(f"  DNSSEC: {resolved_status['dnssec']}")

            if resolved_status['cache_statistics']:
                stats = resolved_status['cache_statistics']
                if 'current_cache_size' in stats:
                    output.append(f"  Cache entries: {stats['current_cache_size']}")
                if 'cache_hits' in stats and 'cache_misses' in stats:
                    total = stats['cache_hits'] + stats['cache_misses']
                    if total > 0:
                        hit_rate = (stats['cache_hits'] / total) * 100
                        output.append(f"  Cache hit rate: {hit_rate:.1f}%")

        output.append("")

    # Issues and warnings
    if issues:
        output.append("Issues:")
        output.append("-" * 40)
        for issue in issues:
            severity = issue['severity'].upper()
            output.append(f"  [{severity}] {issue['message']}")
        output.append("")

    if warnings:
        output.append("Warnings:")
        output.append("-" * 40)
        for warning in warnings:
            output.append(f"  [WARNING] {warning['message']}")
        output.append("")

    # Summary
    if not issues and not warnings:
        output.append("Status: All DNS resolvers healthy")
    elif not issues:
        output.append(f"Status: DNS functional with {len(warnings)} warning(s)")
    else:
        critical_count = sum(1 for i in issues if i['severity'] == 'critical')
        output.append(f"Status: {len(issues)} issue(s) detected ({critical_count} critical)")

    return '\n'.join(output)


def format_json(resolv_conf, resolved_status, nameserver_results,
                resolution_tests, issues, warnings):
    """Format DNS health data as JSON."""
    data = {
        'resolv_conf': resolv_conf,
        'systemd_resolved': resolved_status,
        'nameserver_reachability': nameserver_results,
        'resolution_tests': resolution_tests,
        'issues': issues,
        'warnings': warnings,
        'healthy': len([i for i in issues if i['severity'] == 'critical']) == 0
    }
    return json.dumps(data, indent=2)


def format_table(resolv_conf, resolved_status, nameserver_results,
                 resolution_tests, issues, warnings):
    """Format DNS health data as a table."""
    output = []

    # Nameserver table
    output.append(f"{'NAMESERVER':<20} {'STATUS':<12} {'LATENCY':<12} {'ERROR':<30}")
    output.append("-" * 74)

    for ns_result in nameserver_results:
        ns = ns_result['nameserver'][:20]
        status = "OK" if ns_result['reachable'] else "FAIL"
        latency = f"{ns_result['latency_ms']:.0f}ms" if ns_result['latency_ms'] else "-"
        error = (ns_result['error'] or "-")[:30]
        output.append(f"{ns:<20} {status:<12} {latency:<12} {error:<30}")

    output.append("")

    # Resolution tests table
    if resolution_tests:
        output.append(f"{'DOMAIN':<30} {'STATUS':<12} {'RESULT':<30}")
        output.append("-" * 72)

        for res_test in resolution_tests:
            domain = res_test['domain'][:30]
            status = "OK" if res_test['resolved'] else "FAIL"
            if res_test['resolved']:
                result = ', '.join(res_test['addresses'][:2])[:30]
            else:
                result = (res_test['error'] or "unknown")[:30]
            output.append(f"{domain:<30} {status:<12} {result:<30}")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor DNS resolver configuration and health.',
        epilog='''
Examples:
  # Check DNS resolver health
  %(prog)s

  # Show detailed information including systemd-resolved stats
  %(prog)s --verbose

  # Output as JSON for monitoring systems
  %(prog)s --format json

  # Test resolution of specific domains
  %(prog)s --test-domain example.com --test-domain internal.corp

  # Skip nameserver reachability tests
  %(prog)s --no-reachability

  # Only show issues
  %(prog)s --warn-only

Exit codes:
  0 - All resolvers healthy
  1 - DNS issues detected
  2 - Usage error
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
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
        help='Show detailed information including cache statistics'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '--no-reachability',
        action='store_true',
        help='Skip nameserver reachability tests'
    )

    parser.add_argument(
        '--no-resolution',
        action='store_true',
        help='Skip DNS resolution tests'
    )

    parser.add_argument(
        '--test-domain',
        action='append',
        dest='test_domains',
        metavar='DOMAIN',
        help='Additional domain to test resolution (can be repeated)'
    )

    parser.add_argument(
        '--timeout',
        type=float,
        default=2.0,
        help='Timeout in seconds for DNS tests (default: 2.0)'
    )

    parser.add_argument(
        '--resolv-conf',
        default='/etc/resolv.conf',
        help='Path to resolv.conf (default: /etc/resolv.conf)'
    )

    args = parser.parse_args()

    # Validate timeout
    if args.timeout <= 0:
        print("Error: Timeout must be a positive number", file=sys.stderr)
        return 2

    # Read resolv.conf
    resolv_conf = read_resolv_conf(args.resolv_conf)

    # Check systemd-resolved status
    resolved_status = check_systemd_resolved()

    # Test nameserver reachability
    nameserver_results = []
    if not args.no_reachability and resolv_conf['nameservers']:
        for ns in resolv_conf['nameservers']:
            # Skip loopback addresses if systemd-resolved is running
            if ns in ('127.0.0.53', '127.0.0.1') and resolved_status and resolved_status['running']:
                # Test anyway but it should work
                pass
            result = test_nameserver_reachability(ns, timeout=args.timeout)
            nameserver_results.append(result)

    # Test DNS resolution
    resolution_tests = []
    if not args.no_resolution:
        # Default test domains
        test_domains = ['google.com', 'cloudflare.com']
        if args.test_domains:
            test_domains.extend(args.test_domains)

        for domain in test_domains:
            result = test_dns_resolution(domain, timeout=args.timeout)
            resolution_tests.append(result)

    # Analyze health
    issues, warnings = analyze_dns_health(
        resolv_conf,
        resolved_status,
        nameserver_results,
        resolution_tests
    )

    # Filter for warn-only mode
    if args.warn_only and not issues and not warnings:
        if args.format == 'json':
            print(json.dumps({'healthy': True, 'issues': [], 'warnings': []}))
        else:
            print("All DNS resolvers healthy - no issues to report")
        return 0

    # Format output
    if args.format == 'json':
        output = format_json(
            resolv_conf, resolved_status, nameserver_results,
            resolution_tests, issues, warnings
        )
    elif args.format == 'table':
        output = format_table(
            resolv_conf, resolved_status, nameserver_results,
            resolution_tests, issues, warnings
        )
    else:
        output = format_plain(
            resolv_conf, resolved_status, nameserver_results,
            resolution_tests, issues, warnings, args.verbose
        )

    print(output)

    # Return exit code based on issues
    critical_issues = [i for i in issues if i['severity'] == 'critical']
    if critical_issues:
        return 1
    elif issues:
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
