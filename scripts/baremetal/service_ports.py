#!/usr/bin/env python3
# boxctl:
#   category: baremetal/network
#   tags: [network, ports, services, monitoring, connectivity]
#   requires: []
#   privilege: user
#   related: []
#   brief: Monitor service port availability and responsiveness

"""
Monitor service port availability and responsiveness on baremetal systems.

Checks whether critical services are listening on expected ports and optionally
tests basic connectivity. Useful for monitoring database, web, cache, and other
services in large-scale baremetal environments without requiring service-specific
clients.

Supports common service presets (http, https, ssh, mysql, postgres, redis, etc.)
and custom port definitions with optional protocol checks.
"""

import argparse
import socket
import ssl
import time
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


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
    'kafka': {'port': 9092, 'protocol': 'tcp', 'check': 'connect'},
    'zookeeper': {'port': 2181, 'protocol': 'tcp', 'check': 'connect'},
    'etcd': {'port': 2379, 'protocol': 'tcp', 'check': 'http'},
    'consul': {'port': 8500, 'protocol': 'tcp', 'check': 'http'},
    'prometheus': {'port': 9090, 'protocol': 'tcp', 'check': 'http'},
    'grafana': {'port': 3000, 'protocol': 'tcp', 'check': 'http'},
    'dns': {'port': 53, 'protocol': 'udp', 'check': 'connect'},
    'ntp': {'port': 123, 'protocol': 'udp', 'check': 'connect'},
    'smtp': {'port': 25, 'protocol': 'tcp', 'check': 'banner'},
}


def parse_service_spec(spec: str) -> tuple[dict | None, str | None]:
    """
    Parse a service specification string.

    Formats:
        - preset name: 'redis', 'mysql', 'http'
        - host:port: 'localhost:8080'
        - host:port:protocol: 'localhost:53:udp'
        - preset@host: 'redis@10.0.0.1'
        - preset@host:port: 'http@10.0.0.1:8080'
    """
    result = {
        'host': 'localhost',
        'port': None,
        'protocol': 'tcp',
        'check': 'connect',
        'name': spec,
        'original_spec': spec
    }

    if '@' in spec:
        preset_part, host_part = spec.split('@', 1)

        if preset_part.lower() in SERVICE_PRESETS:
            preset = SERVICE_PRESETS[preset_part.lower()]
            result['port'] = preset['port']
            result['protocol'] = preset['protocol']
            result['check'] = preset['check']
            result['name'] = preset_part.lower()
        else:
            return None, f"Unknown service preset: {preset_part}"

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

    elif spec.lower() in SERVICE_PRESETS:
        preset = SERVICE_PRESETS[spec.lower()]
        result['port'] = preset['port']
        result['protocol'] = preset['protocol']
        result['check'] = preset['check']
        result['name'] = spec.lower()

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

    if result['port'] is None:
        return None, f"No port specified for: {spec}"

    if result['port'] < 1 or result['port'] > 65535:
        return None, f"Port out of range (1-65535): {result['port']}"

    if result['protocol'] not in ('tcp', 'udp'):
        return None, f"Invalid protocol (must be tcp or udp): {result['protocol']}"

    return result, None


def check_tcp_connect(host: str, port: int, timeout: float) -> dict:
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
        result['latency_ms'] = round((end_time - start_time) * 1000, 1)
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


def check_udp_connect(host: str, port: int, timeout: float) -> dict:
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

        sock.sendto(b'\x00', (host, port))
        end_time = time.time()

        result['reachable'] = True
        result['latency_ms'] = round((end_time - start_time) * 1000, 1)
        sock.close()

    except socket.timeout:
        result['reachable'] = True
        result['note'] = 'UDP probe sent (no response expected)'
    except socket.gaierror as e:
        result['error'] = f'DNS resolution failed: {e}'
    except OSError as e:
        result['error'] = str(e)

    return result


def check_tcp_banner(host: str, port: int, timeout: float) -> dict:
    """Test TCP connection and read initial banner."""
    result = check_tcp_connect(host, port, timeout)

    if result['reachable']:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            sock.settimeout(min(timeout, 2.0))
            banner = sock.recv(256)
            result['banner'] = banner.decode('utf-8', errors='replace').strip()[:100]
            sock.close()

        except socket.timeout:
            result['banner'] = None
        except Exception:
            result['banner'] = None

    return result


def check_http(host: str, port: int, timeout: float, use_ssl: bool = False) -> dict:
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

            request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())

            response = sock.recv(1024).decode('utf-8', errors='replace')
            sock.close()

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


def check_redis(host: str, port: int, timeout: float) -> dict:
    """Test Redis connectivity with PING command."""
    result = check_tcp_connect(host, port, timeout)

    if result['reachable']:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            sock.sendall(b"*1\r\n$4\r\nPING\r\n")

            response = sock.recv(128).decode('utf-8', errors='replace')
            sock.close()

            if '+PONG' in response:
                result['redis_ping'] = 'PONG'
            elif '-NOAUTH' in response or '-ERR' in response:
                result['redis_ping'] = 'auth_required'
            else:
                result['redis_ping'] = response.strip()[:50]

        except Exception as e:
            result['redis_error'] = str(e)

    return result


def check_service(service: dict, timeout: float) -> dict:
    """Check a service based on its configuration."""
    host = service['host']
    port = service['port']
    protocol = service['protocol']
    check_type = service['check']

    if protocol == 'udp':
        return check_udp_connect(host, port, timeout)

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


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = all reachable, 1 = some unreachable, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Monitor service port availability and responsiveness"
    )
    parser.add_argument('services', nargs='*', metavar='SERVICE',
                        help='Service specifications to check')
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show detailed information (banners, extra data)")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("-t", "--timeout", type=float, default=5.0,
                        help="Connection timeout in seconds (default: 5.0)")
    parser.add_argument("--list-presets", action="store_true",
                        help="List all available service presets")
    opts = parser.parse_args(args)

    # List presets and exit
    if opts.list_presets:
        presets = []
        for name, config in sorted(SERVICE_PRESETS.items()):
            presets.append({
                'name': name,
                'port': config['port'],
                'protocol': config['protocol'],
                'check': config['check']
            })
        output.emit({'presets': presets})
        output.set_summary(f"{len(presets)} presets available")
        return 0

    # Validate timeout
    if opts.timeout <= 0:
        output.error("Timeout must be a positive number")
        return 2

    # Require at least one service
    if not opts.services:
        output.error("At least one service specification required")
        return 2

    # Parse service specifications
    services = []
    for spec in opts.services:
        service, error = parse_service_spec(spec)
        if error:
            output.error(error)
            return 2
        services.append(service)

    # Check each service
    results = []
    for service in services:
        result = check_service(service, opts.timeout)
        results.append({
            'service': service,
            'result': result
        })

    # Build output
    reachable = [r for r in results if r['result']['reachable']]
    unreachable = [r for r in results if not r['result']['reachable']]

    service_data = []
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

        if opts.verbose:
            for key in ['http_status', 'http_version', 'banner', 'redis_ping']:
                if key in res:
                    entry[key] = res[key]

        service_data.append(entry)

    output.emit({
        'services': service_data,
        'total': len(results),
        'reachable_count': len(reachable),
        'unreachable_count': len(unreachable),
    })

    # Set summary
    if len(unreachable) == 0:
        output.set_summary(f"All {len(results)} service(s) reachable")
    else:
        output.set_summary(f"{len(unreachable)}/{len(results)} service(s) unreachable")

    return 1 if unreachable else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
