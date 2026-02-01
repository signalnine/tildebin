#!/usr/bin/env python3
"""
Monitor container runtime health on baremetal systems.

This script monitors the health of container runtimes (Docker, containerd, podman)
running on baremetal hosts. Useful for:

- Detecting container runtime service failures before they impact workloads
- Monitoring disk space in container storage paths (/var/lib/docker, etc.)
- Identifying stale or dead containers consuming resources
- Tracking image storage growth and cleanup needs
- Verifying runtime socket availability for orchestrators

The script checks service status, storage usage, container states, and
runtime responsiveness. Supports multiple runtimes simultaneously.

Exit codes:
    0 - All container runtimes healthy, no issues detected
    1 - Warnings or errors found (service issues, high disk usage, dead containers)
    2 - Usage error or no container runtime found
"""

import argparse
import subprocess
import sys
import json
import os


def run_command(cmd, timeout=30):
    """Execute shell command and return result.

    Args:
        cmd: Command as list or string
        timeout: Timeout in seconds

    Returns:
        tuple: (return_code, stdout, stderr)
    """
    try:
        if isinstance(cmd, str):
            cmd = cmd.split()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -2, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_tool_available(tool_name):
    """Check if a system tool is available."""
    rc, _, _ = run_command(['which', tool_name])
    return rc == 0


def detect_runtimes():
    """Detect which container runtimes are installed.

    Returns:
        list: List of detected runtime names
    """
    runtimes = []

    # Check for Docker
    if check_tool_available('docker'):
        runtimes.append('docker')

    # Check for containerd (ctr)
    if check_tool_available('ctr'):
        runtimes.append('containerd')

    # Check for podman
    if check_tool_available('podman'):
        runtimes.append('podman')

    return runtimes


def check_systemd_service(service_name):
    """Check systemd service status.

    Args:
        service_name: Name of the systemd service

    Returns:
        dict: Service status information
    """
    result = {
        'service': service_name,
        'active': False,
        'status': 'unknown',
        'enabled': False
    }

    # Check if service is active
    rc, stdout, _ = run_command(['systemctl', 'is-active', service_name])
    result['status'] = stdout.strip()
    result['active'] = (rc == 0)

    # Check if service is enabled
    rc, stdout, _ = run_command(['systemctl', 'is-enabled', service_name])
    result['enabled'] = (rc == 0)

    return result


def get_storage_usage(path):
    """Get disk usage for a path.

    Args:
        path: Filesystem path to check

    Returns:
        dict: Storage usage information or None if path doesn't exist
    """
    if not os.path.exists(path):
        return None

    try:
        stat = os.statvfs(path)
        total = stat.f_blocks * stat.f_frsize
        free = stat.f_bfree * stat.f_frsize
        used = total - free

        return {
            'path': path,
            'total_bytes': total,
            'used_bytes': used,
            'free_bytes': free,
            'usage_percent': (used / total * 100) if total > 0 else 0
        }
    except Exception:
        return None


def check_docker_health(storage_threshold):
    """Check Docker runtime health.

    Args:
        storage_threshold: Storage warning threshold percentage

    Returns:
        dict: Docker health information with issues list
    """
    result = {
        'runtime': 'docker',
        'available': True,
        'service': None,
        'storage': None,
        'containers': {'total': 0, 'running': 0, 'stopped': 0, 'dead': 0},
        'images': {'total': 0, 'dangling': 0},
        'responsive': False,
        'issues': []
    }

    # Check Docker service
    result['service'] = check_systemd_service('docker')
    if not result['service']['active']:
        result['issues'].append({
            'severity': 'CRITICAL',
            'message': 'Docker service is not running'
        })

    # Check storage
    storage_paths = ['/var/lib/docker', '/var/lib/containers/storage']
    for path in storage_paths:
        storage = get_storage_usage(path)
        if storage:
            result['storage'] = storage
            if storage['usage_percent'] >= storage_threshold:
                result['issues'].append({
                    'severity': 'WARNING',
                    'message': f"Docker storage {storage['usage_percent']:.1f}% used at {path}"
                })
            break

    # Check Docker responsiveness
    rc, stdout, stderr = run_command(['docker', 'info', '--format', '{{.ServerVersion}}'], timeout=10)
    if rc == 0:
        result['responsive'] = True
        result['version'] = stdout.strip()
    else:
        result['issues'].append({
            'severity': 'CRITICAL',
            'message': f'Docker daemon not responsive: {stderr.strip()}'
        })
        return result

    # Get container counts
    rc, stdout, _ = run_command(['docker', 'ps', '-a', '--format', '{{.State}}'])
    if rc == 0:
        states = stdout.strip().split('\n') if stdout.strip() else []
        result['containers']['total'] = len(states)
        result['containers']['running'] = states.count('running')
        result['containers']['stopped'] = states.count('exited')
        result['containers']['dead'] = states.count('dead')

        if result['containers']['dead'] > 0:
            result['issues'].append({
                'severity': 'WARNING',
                'message': f"{result['containers']['dead']} dead container(s) found"
            })

    # Get image counts
    rc, stdout, _ = run_command(['docker', 'images', '-q'])
    if rc == 0:
        images = stdout.strip().split('\n') if stdout.strip() else []
        result['images']['total'] = len([i for i in images if i])

    # Check for dangling images
    rc, stdout, _ = run_command(['docker', 'images', '-f', 'dangling=true', '-q'])
    if rc == 0:
        dangling = stdout.strip().split('\n') if stdout.strip() else []
        result['images']['dangling'] = len([i for i in dangling if i])
        if result['images']['dangling'] > 10:
            result['issues'].append({
                'severity': 'INFO',
                'message': f"{result['images']['dangling']} dangling images (consider docker image prune)"
            })

    return result


def check_containerd_health(storage_threshold):
    """Check containerd runtime health.

    Args:
        storage_threshold: Storage warning threshold percentage

    Returns:
        dict: containerd health information with issues list
    """
    result = {
        'runtime': 'containerd',
        'available': True,
        'service': None,
        'storage': None,
        'responsive': False,
        'issues': []
    }

    # Check containerd service
    result['service'] = check_systemd_service('containerd')
    if not result['service']['active']:
        result['issues'].append({
            'severity': 'CRITICAL',
            'message': 'containerd service is not running'
        })

    # Check storage
    storage_paths = ['/var/lib/containerd', '/run/containerd']
    for path in storage_paths:
        storage = get_storage_usage(path)
        if storage:
            result['storage'] = storage
            if storage['usage_percent'] >= storage_threshold:
                result['issues'].append({
                    'severity': 'WARNING',
                    'message': f"containerd storage {storage['usage_percent']:.1f}% used at {path}"
                })
            break

    # Check containerd responsiveness
    rc, stdout, stderr = run_command(['ctr', 'version'], timeout=10)
    if rc == 0:
        result['responsive'] = True
        # Parse version from output
        for line in stdout.split('\n'):
            if 'Version:' in line:
                result['version'] = line.split(':', 1)[1].strip()
                break
    else:
        result['issues'].append({
            'severity': 'CRITICAL',
            'message': f'containerd not responsive: {stderr.strip()}'
        })

    return result


def check_podman_health(storage_threshold):
    """Check Podman runtime health.

    Args:
        storage_threshold: Storage warning threshold percentage

    Returns:
        dict: Podman health information with issues list
    """
    result = {
        'runtime': 'podman',
        'available': True,
        'service': None,
        'storage': None,
        'containers': {'total': 0, 'running': 0, 'stopped': 0},
        'images': {'total': 0, 'dangling': 0},
        'responsive': False,
        'issues': []
    }

    # Check podman socket service (if using systemd socket activation)
    result['service'] = check_systemd_service('podman.socket')

    # Check storage
    storage_paths = ['/var/lib/containers/storage', os.path.expanduser('~/.local/share/containers')]
    for path in storage_paths:
        storage = get_storage_usage(path)
        if storage:
            result['storage'] = storage
            if storage['usage_percent'] >= storage_threshold:
                result['issues'].append({
                    'severity': 'WARNING',
                    'message': f"Podman storage {storage['usage_percent']:.1f}% used at {path}"
                })
            break

    # Check Podman responsiveness
    rc, stdout, stderr = run_command(['podman', 'version', '--format', '{{.Client.Version}}'], timeout=10)
    if rc == 0:
        result['responsive'] = True
        result['version'] = stdout.strip()
    else:
        # Podman may work without a daemon for rootless mode
        rc, stdout, _ = run_command(['podman', 'info', '--format', '{{.Version.Version}}'], timeout=10)
        if rc == 0:
            result['responsive'] = True
            result['version'] = stdout.strip()
        else:
            result['issues'].append({
                'severity': 'WARNING',
                'message': f'Podman not fully responsive: {stderr.strip()}'
            })
            return result

    # Get container counts
    rc, stdout, _ = run_command(['podman', 'ps', '-a', '--format', '{{.State}}'])
    if rc == 0:
        states = stdout.strip().split('\n') if stdout.strip() else []
        result['containers']['total'] = len([s for s in states if s])
        result['containers']['running'] = states.count('running')
        result['containers']['stopped'] = states.count('exited')

    # Get image counts
    rc, stdout, _ = run_command(['podman', 'images', '-q'])
    if rc == 0:
        images = stdout.strip().split('\n') if stdout.strip() else []
        result['images']['total'] = len([i for i in images if i])

    # Check for dangling images
    rc, stdout, _ = run_command(['podman', 'images', '-f', 'dangling=true', '-q'])
    if rc == 0:
        dangling = stdout.strip().split('\n') if stdout.strip() else []
        result['images']['dangling'] = len([i for i in dangling if i])
        if result['images']['dangling'] > 10:
            result['issues'].append({
                'severity': 'INFO',
                'message': f"{result['images']['dangling']} dangling images (consider podman image prune)"
            })

    return result


def format_bytes(bytes_val):
    """Format bytes to human readable format."""
    if bytes_val >= 1024 ** 3:
        return f"{bytes_val / (1024 ** 3):.1f} GB"
    elif bytes_val >= 1024 ** 2:
        return f"{bytes_val / (1024 ** 2):.1f} MB"
    elif bytes_val >= 1024:
        return f"{bytes_val / 1024:.1f} KB"
    else:
        return f"{bytes_val} B"


def output_plain(results, verbose, warn_only):
    """Output results in plain text format."""
    for result in results:
        runtime = result['runtime']
        issues = result.get('issues', [])

        # Skip if no issues and warn_only mode
        if warn_only and not any(i['severity'] in ['CRITICAL', 'WARNING'] for i in issues):
            continue

        print(f"=== {runtime.upper()} ===")

        if result.get('responsive'):
            version = result.get('version', 'unknown')
            print(f"Status: Running (version {version})")
        else:
            print("Status: Not responsive")

        service = result.get('service')
        if service:
            status = 'active' if service['active'] else 'inactive'
            enabled = 'enabled' if service['enabled'] else 'disabled'
            print(f"Service: {status} ({enabled})")

        storage = result.get('storage')
        if storage and verbose:
            print(f"Storage: {format_bytes(storage['used_bytes'])} / {format_bytes(storage['total_bytes'])} "
                  f"({storage['usage_percent']:.1f}% used)")

        containers = result.get('containers')
        if containers and verbose:
            print(f"Containers: {containers['total']} total, {containers['running']} running, "
                  f"{containers['stopped']} stopped")
            if containers.get('dead', 0) > 0:
                print(f"  Dead containers: {containers['dead']}")

        images = result.get('images')
        if images and verbose:
            print(f"Images: {images['total']} total, {images['dangling']} dangling")

        # Print issues
        for issue in issues:
            severity = issue['severity']
            if warn_only and severity == 'INFO':
                continue
            print(f"[{severity}] {issue['message']}")

        print()


def output_json(results):
    """Output results in JSON format."""
    output = {
        'runtimes': results,
        'summary': {
            'total_runtimes': len(results),
            'healthy': sum(1 for r in results if r.get('responsive') and
                          not any(i['severity'] == 'CRITICAL' for i in r.get('issues', []))),
            'has_warnings': any(any(i['severity'] == 'WARNING' for i in r.get('issues', [])) for r in results),
            'has_errors': any(any(i['severity'] == 'CRITICAL' for i in r.get('issues', [])) for r in results)
        }
    }
    print(json.dumps(output, indent=2))


def output_table(results, verbose, warn_only):
    """Output results in table format."""
    print("=" * 80)
    print("CONTAINER RUNTIME HEALTH SUMMARY")
    print("=" * 80)
    print(f"{'Runtime':<15} {'Status':<12} {'Version':<15} {'Containers':<15} {'Issues':<10}")
    print("-" * 80)

    for result in results:
        runtime = result['runtime']
        status = 'OK' if result.get('responsive') else 'DOWN'
        version = result.get('version', 'N/A')[:14]

        containers = result.get('containers', {})
        container_str = f"{containers.get('running', 0)}/{containers.get('total', 0)}"

        issues = result.get('issues', [])
        critical = sum(1 for i in issues if i['severity'] == 'CRITICAL')
        warnings = sum(1 for i in issues if i['severity'] == 'WARNING')
        issue_str = f"{critical}C/{warnings}W"

        print(f"{runtime:<15} {status:<12} {version:<15} {container_str:<15} {issue_str:<10}")

    print("=" * 80)
    print()

    # Print all issues
    all_issues = []
    for result in results:
        for issue in result.get('issues', []):
            if warn_only and issue['severity'] == 'INFO':
                continue
            all_issues.append((result['runtime'], issue))

    if all_issues:
        print("ISSUES DETECTED")
        print("-" * 80)
        for runtime, issue in all_issues:
            print(f"[{issue['severity']}] {runtime}: {issue['message']}")
        print()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Monitor container runtime health on baremetal systems',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                      # Check all detected runtimes
  %(prog)s --runtime docker     # Check Docker only
  %(prog)s --format json        # JSON output for monitoring tools
  %(prog)s --storage-warn 80    # Warn when storage exceeds 80%%
  %(prog)s --verbose            # Show detailed information

Supported runtimes:
  docker      - Docker Engine
  containerd  - containerd (ctr)
  podman      - Podman

Exit codes:
  0 - All runtimes healthy
  1 - Warnings or critical issues detected
  2 - Usage error or no container runtime found
        """
    )

    parser.add_argument(
        '--runtime',
        choices=['docker', 'containerd', 'podman'],
        action='append',
        help='Specific runtime(s) to check (default: auto-detect)'
    )

    parser.add_argument(
        '--format',
        choices=['plain', 'json', 'table'],
        default='plain',
        help='Output format (default: %(default)s)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and errors'
    )

    parser.add_argument(
        '--storage-warn',
        type=float,
        default=85.0,
        metavar='PCT',
        help='Storage warning threshold percentage (default: 85%%)'
    )

    args = parser.parse_args()

    # Validate storage threshold
    if args.storage_warn < 0 or args.storage_warn > 100:
        print("Error: --storage-warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    # Detect or use specified runtimes
    if args.runtime:
        runtimes = args.runtime
    else:
        runtimes = detect_runtimes()

    if not runtimes:
        print("Error: No container runtimes detected", file=sys.stderr)
        print("Install one of: docker, containerd (ctr), podman", file=sys.stderr)
        sys.exit(2)

    # Check each runtime
    results = []
    for runtime in runtimes:
        if runtime == 'docker':
            results.append(check_docker_health(args.storage_warn))
        elif runtime == 'containerd':
            results.append(check_containerd_health(args.storage_warn))
        elif runtime == 'podman':
            results.append(check_podman_health(args.storage_warn))

    # Output results
    if args.format == 'json':
        output_json(results)
    elif args.format == 'table':
        output_table(results, args.verbose, args.warn_only)
    else:
        output_plain(results, args.verbose, args.warn_only)

    # Determine exit code
    has_critical = any(
        any(i['severity'] == 'CRITICAL' for i in r.get('issues', []))
        for r in results
    )
    has_warning = any(
        any(i['severity'] == 'WARNING' for i in r.get('issues', []))
        for r in results
    )

    if has_critical or has_warning:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    main()
