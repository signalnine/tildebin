#!/usr/bin/env python3
"""
Monitor service port availability and responsiveness on baremetal systems.

Checks whether critical services are listening on expected ports and optionally
tests basic connectivity. Useful for monitoring database, web, cache, and other
services in large-scale baremetal environments without requiring service-specific
clients.

Supports common service presets (http, https, ssh, mysql, postgres, redis, etc.)
and custom port definitions with optional protocol checks.

Exit codes:
    0 - All monitored services are reachable
    1 - One or more services are unreachable or not responding
    2 - Usage error or invalid configuration
"""

import argparse
import json
import socket
import ssl
import sys
import time


# Common service presets with default ports and protocols
SERVICE_PRESETS = {
    'ssh': {'port': 22, 'protocol': 'tcp', 'check': 'banner'},
    'http': {'port': 80, 'protocol': 'tcp', 'check': 'http'},
    'https': {'port': 443, 'protocol': 'tcp', 'check': 'https'},
    'mysql': {'port': 3306, 'protocol': 'tcp', 'check': 'connect'},
    'postgres': {'port': 5432, 'protocol': 'tcp', 'check': 'connect'},
    'redis': {'port': 6379, 'protocol': 'tcp', 'check': 'redis'},
    'memcached': {'port': 11211, 'protocol': 'tcp', 'check': 'connect'},
    'mongodb': {'port': 27017, 'protocol': 'tcp', 'check': 'connect'},
    'elasticsearch': {'port': 9200, 'protocol': 'tcp', 'check': 'http'},
    'rabbitmq': {'port': 5672, 'protocol': 'tcp', 'check': 'connect'},
    'rabbitmq-mgmt': {'port': 15672, 'protocol': 'tcp', 'check': 'http'},
    'kafka': {'port': 9092, 'protocol': 'tcp', 'check': 'connect'},
    'zookeeper': {'port': 2181, 'protocol': 'tcp', 'check': 'connect'},
    'etcd': {'port': 2379, 'protocol': 'tcp', 'check': 'http'},
    'consul': {'port': 8500, 'protocol': 'tcp', 'check': 'http'},
    'vault': {'port': 8200, 'protocol': 'tcp', 'check': 'https'},
    'prometheus': {'port': 9090, 'protocol': 'tcp', 'check': 'http'},
    'grafana': {'port': 3000, 'protocol': 'tcp', 'check': 'http'},
    'nginx': {'port': 80, 'protocol': 'tcp', 'check': 'http'},
    'apache': {'port': 80, 'protocol': 'tcp', 'check': 'http'},
    'dns': {'port': 53, 'protocol': 'udp', 'check': 'connect'},
    'ntp': {'port': 123, 'protocol': 'udp', 'check': 'connect'},
    'ldap': {'port': 389, 'protocol': 'tcp', 'check': 'connect'},
    'ldaps': {'port': 636, 'protocol': 'tcp', 'check': 'connect'},
    'smtp': {'port': 25, 'protocol': 'tcp', 'check': 'banner'},
    'smtps': {'port': 465, 'protocol': 'tcp', 'check': 'connect'},
    'imap': {'port': 143, 'protocol': 'tcp', 'check': 'banner'},
    'imaps': {'port': 993, 'protocol': 'tcp', 'check': 'connect'},
    'pop3': {'port': 110, 'protocol': 'tcp', 'check': 'banner'},
    'pop3s': {'port': 995, 'protocol': 'tcp', 'check': 'connect'},
    'ftp': {'port': 21, 'protocol': 'tcp', 'check': 'banner'},
    'minio': {'port': 9000, 'protocol': 'tcp', 'check': 'http'},
}


def parse_service_spec(spec):
    """
    Parse a service specification string.

    Formats:
        - preset name: 'redis', 'mysql', 'http'
        - host:port: 'localhost:8080'
        - host:port:protocol: 'localhost:53:udp'
        - preset@host: 'redis@10.0.0.1'
        - preset@host:port: 'http@10.0.0.1:8080'

    Returns dict with: host, port, protocol, check, name
    """
    result = {
        'host': 'localhost',
        'port': None,
        'protocol': 'tcp',
        'check': 'connect',
        'name': spec,
        'original_spec': spec
    }

    # Check for preset@host format
    if '@' in spec:
        preset_part, host_part = spec.split('@', 1)

        # Check if preset exists
        if preset_part.lower() in SERVICE_PRESETS:
            preset = SERVICE_PRESETS[preset_part.lower()]
            result['port'] = preset['port']
            result['protocol'] = preset['protocol']
            result['check'] = preset['check']
            result['name'] = preset_part.lower()
        else:
            return None, f"Unknown service preset: {preset_part}"

        # Parse host part (may include custom port)
        if ':' in host_part:
            parts = host_part.split(':')
            result['host'] = parts[0]
            try:
                result['port'] = int(parts[1])
            except ValueError:
                return None, f"Invalid port number: {parts[1]}"
            if len(parts) > 2:
                result['protocol'] = parts[2].lower()
        else:
            result['host'] = host_part

    # Check for preset name only
    elif spec.lower() in SERVICE_PRESETS:
        preset = SERVICE_PRESETS[spec.lower()]
        result['port'] = preset['port']
        result['protocol'] = preset['protocol']
        result['check'] = preset['check']
        result['name'] = spec.lower()

    # Parse host:port[:protocol] format
    elif ':' in spec:
        parts = spec.split(':')
        result['host'] = parts[0] if parts[0] else 'localhost'
        try:
            result['port'] = int(parts[1])
        except ValueError:
            return None, f"Invalid port number: {parts[1]}"
        if len(parts) > 2:
            result['protocol'] = parts[2].lower()
        result['name'] = f"{result['host']}:{result['port']}"

    else:
        return None, f"Invalid service specification: {spec}"

    # Validate
    if result['port'] is None:
        return None, f"No port specified for: {spec}"

    if result['port'] < 1 or result['port'] > 65535:
        return None, f"Port out of range (1-65535): {result['port']}"

    if result['protocol'] not in ('tcp', 'udp'):
        return None, f"Invalid protocol (must be tcp or udp): {result['protocol']}"

    return result, None


def check_tcp_connect(host, port, timeout):
    """Test basic TCP connection to host:port."""
    result = {
        'reachable': False,
        'latency_ms': None,
        'error': None
    }

    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        end_time = time.time()

        result['reachable'] = True
        result['latency_ms'] = (end_time - start_time) * 1000
        sock.close()

    except socket.timeout:
        result['error'] = 'connection timed out'
    except ConnectionRefusedError:
        result['error'] = 'connection refused'
    except socket.gaierror as e:
        result['error'] = f'DNS resolution failed: {e}'
    except OSError as e:
        result['error'] = str(e)

    return result


def check_udp_connect(host, port, timeout):
    """Test basic UDP connectivity to host:port."""
    result = {
        'reachable': False,
        'latency_ms': None,
        'error': None,
        'note': 'UDP connectivity is best-effort'
    }

    try:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Send a minimal probe
        sock.sendto(b'\x00', (host, port))

        # UDP is connectionless, so we can't really verify
        # Just check if we can send without error
        end_time = time.time()

        result['reachable'] = True
        result['latency_ms'] = (end_time - start_time) * 1000
        sock.close()

    except socket.timeout:
        # For UDP, timeout doesn't necessarily mean failure
        result['reachable'] = True
        result['note'] = 'UDP probe sent (no response expected)'
    except socket.gaierror as e:
        result['error'] = f'DNS resolution failed: {e}'
    except OSError as e:
        result['error'] = str(e)

    return result


def check_tcp_banner(host, port, timeout):
    """Test TCP connection and read initial banner."""
    result = check_tcp_connect(host, port, timeout)

    if result['reachable']:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Try to read banner
            sock.settimeout(min(timeout, 2.0))
            banner = sock.recv(256)
            result['banner'] = banner.decode('utf-8', errors='replace').strip()[:100]
            sock.close()

        except socket.timeout:
            result['banner'] = None
        except Exception:
            result['banner'] = None

    return result


def check_http(host, port, timeout, use_ssl=False):
    """Test HTTP(S) connectivity with a HEAD request."""
    result = check_tcp_connect(host, port, timeout)

    if result['reachable']:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            # Send minimal HTTP request
            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())

            # Read response
            response = sock.recv(1024).decode('utf-8', errors='replace')
            sock.close()

            # Parse status code
            if response.startswith('HTTP/'):
                parts = response.split(' ', 2)
                if len(parts) >= 2:
                    result['http_status'] = int(parts[1])
                    result['http_version'] = parts[0]

        except ssl.SSLError as e:
            result['error'] = f'SSL error: {e}'
            result['reachable'] = False
        except Exception as e:
            result['http_error'] = str(e)

    return result


def check_redis(host, port, timeout):
    """Test Redis connectivity with PING command."""
    result = check_tcp_connect(host, port, timeout)

    if result['reachable']:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send Redis PING command (RESP protocol)
            sock.sendall(b"*1\r\n$4\r\nPING\r\n")

            # Read response
            response = sock.recv(128).decode('utf-8', errors='replace')
            sock.close()

            # Check for PONG response
            if '+PONG' in response:
                result['redis_ping'] = 'PONG'
            elif '-NOAUTH' in response or '-ERR' in response:
                result['redis_ping'] = 'auth_required'
            else:
                result['redis_ping'] = response.strip()[:50]

        except Exception as e:
            result['redis_error'] = str(e)

    return result


def check_service(service, timeout):
    """Check a service based on its configuration."""
    host = service['host']
    port = service['port']
    protocol = service['protocol']
    check_type = service['check']

    if protocol == 'udp':
        return check_udp_connect(host, port, timeout)

    # TCP checks
    if check_type == 'banner':
        return check_tcp_banner(host, port, timeout)
    elif check_type == 'http':
        return check_http(host, port, timeout, use_ssl=False)
    elif check_type == 'https':
        return check_http(host, port, timeout, use_ssl=True)
    elif check_type == 'redis':
        return check_redis(host, port, timeout)
    else:
        return check_tcp_connect(host, port, timeout)


def format_plain(results, verbose=False, warn_only=False):
    """Format results as plain text."""
    output = []

    if not warn_only:
        output.append("Service Port Monitor")
        output.append("=" * 60)
        output.append("")

    # Group by status
    reachable = [r for r in results if r['result']['reachable']]
    unreachable = [r for r in results if not r['result']['reachable']]

    if not warn_only and reachable:
        output.append("Reachable Services:")
        output.append("-" * 40)
        for r in reachable:
            svc = r['service']
            res = r['result']
            latency = f" ({res['latency_ms']:.0f}ms)" if res.get('latency_ms') else ""

            extra = []
            if res.get('http_status'):
                extra.append(f"HTTP {res['http_status']}")
            if res.get('redis_ping'):
                extra.append(f"PING={res['redis_ping']}")
            if res.get('banner') and verbose:
                extra.append(f'"{res["banner"][:30]}"')

            extra_str = f" [{', '.join(extra)}]" if extra else ""
            output.append(f"  [OK] {svc['name']} @ {svc['host']}:{svc['port']}{latency}{extra_str}")
        output.append("")

    if unreachable:
        output.append("Unreachable Services:")
        output.append("-" * 40)
        for r in unreachable:
            svc = r['service']
            res = r['result']
            error = res.get('error', 'unknown error')
            output.append(f"  [FAIL] {svc['name']} @ {svc['host']}:{svc['port']} - {error}")
        output.append("")

    # Summary
    total = len(results)
    ok_count = len(reachable)
    fail_count = len(unreachable)

    if fail_count == 0:
        output.append(f"Status: All {total} service(s) reachable")
    else:
        output.append(f"Status: {fail_count}/{total} service(s) unreachable")

    return '\n'.join(output)


def format_json(results):
    """Format results as JSON."""
    data = {
        'services': [],
        'summary': {
            'total': len(results),
            'reachable': 0,
            'unreachable': 0
        },
        'healthy': True
    }

    for r in results:
        svc = r['service']
        res = r['result']

        entry = {
            'name': svc['name'],
            'host': svc['host'],
            'port': svc['port'],
            'protocol': svc['protocol'],
            'reachable': res['reachable'],
            'latency_ms': res.get('latency_ms'),
            'error': res.get('error')
        }

        # Add extra fields if present
        for key in ['http_status', 'http_version', 'banner', 'redis_ping']:
            if key in res:
                entry[key] = res[key]

        data['services'].append(entry)

        if res['reachable']:
            data['summary']['reachable'] += 1
        else:
            data['summary']['unreachable'] += 1
            data['healthy'] = False

    return json.dumps(data, indent=2)


def format_table(results):
    """Format results as a table."""
    output = []

    output.append(f"{'SERVICE':<20} {'HOST':<20} {'PORT':<8} {'STATUS':<10} {'LATENCY':<12} {'ERROR':<25}")
    output.append("-" * 95)

    for r in results:
        svc = r['service']
        res = r['result']

        name = svc['name'][:20]
        host = svc['host'][:20]
        port = str(svc['port'])
        status = "OK" if res['reachable'] else "FAIL"
        latency = f"{res['latency_ms']:.0f}ms" if res.get('latency_ms') else "-"
        error = (res.get('error') or "-")[:25]

        output.append(f"{name:<20} {host:<20} {port:<8} {status:<10} {latency:<12} {error:<25}")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Monitor service port availability and responsiveness.',
        epilog='''
Service specifications:
  Preset names:       ssh, http, https, mysql, postgres, redis, etc.
  Host:port:          localhost:8080
  Host:port:protocol: 10.0.0.1:53:udp
  Preset@host:        redis@10.0.0.1
  Preset@host:port:   http@10.0.0.1:8080

Available presets:
  ssh, http, https, mysql, postgres, redis, memcached, mongodb,
  elasticsearch, rabbitmq, rabbitmq-mgmt, kafka, zookeeper, etcd,
  consul, vault, prometheus, grafana, nginx, apache, dns, ntp,
  ldap, ldaps, smtp, smtps, imap, imaps, pop3, pop3s, ftp, minio

Examples:
  # Check local Redis and MySQL
  %(prog)s redis mysql

  # Check remote services
  %(prog)s redis@10.0.0.1 postgres@db.example.com

  # Check custom port
  %(prog)s http@web.example.com:8080

  # Check multiple services with JSON output
  %(prog)s -f json ssh http https redis

  # Only show failures
  %(prog)s -w redis mysql postgres

Exit codes:
  0 - All services reachable
  1 - One or more services unreachable
  2 - Usage error
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'services',
        nargs='*',
        metavar='SERVICE',
        help='Service specifications to check (see below for formats)'
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
        help='Show detailed information (banners, extra data)'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show unreachable services'
    )

    parser.add_argument(
        '-t', '--timeout',
        type=float,
        default=5.0,
        help='Connection timeout in seconds (default: 5.0)'
    )

    parser.add_argument(
        '--list-presets',
        action='store_true',
        help='List all available service presets and exit'
    )

    args = parser.parse_args()

    # List presets and exit
    if args.list_presets:
        print("Available service presets:")
        print("-" * 50)
        for name, config in sorted(SERVICE_PRESETS.items()):
            print(f"  {name:<18} port {config['port']:<5} ({config['protocol']}, {config['check']})")
        return 0

    # Validate timeout
    if args.timeout <= 0:
        print("Error: Timeout must be a positive number", file=sys.stderr)
        return 2

    # Require at least one service
    if not args.services:
        print("Error: At least one service specification required", file=sys.stderr)
        print("Use --help for usage information", file=sys.stderr)
        return 2

    # Parse service specifications
    services = []
    for spec in args.services:
        service, error = parse_service_spec(spec)
        if error:
            print(f"Error: {error}", file=sys.stderr)
            return 2
        services.append(service)

    # Check each service
    results = []
    for service in services:
        result = check_service(service, args.timeout)
        results.append({
            'service': service,
            'result': result
        })

    # Format output
    if args.format == 'json':
        output = format_json(results)
    elif args.format == 'table':
        output = format_table(results)
    else:
        output = format_plain(results, args.verbose, args.warn_only)

    print(output)

    # Return exit code based on results
    unreachable = sum(1 for r in results if not r['result']['reachable'])
    return 1 if unreachable > 0 else 0


if __name__ == '__main__':
    sys.exit(main())
