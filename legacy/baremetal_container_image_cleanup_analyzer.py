#!/usr/bin/env python3
"""
Analyze container image storage and cleanup needs on baremetal systems.

This script examines container image storage usage across Docker, containerd,
and Podman runtimes to identify cleanup opportunities and predict when
garbage collection should be performed. It helps administrators proactively
manage container image disk usage before it becomes critical.

Useful for:
- Identifying hosts that need image cleanup before disk pressure
- Estimating space that can be recovered by running image prune
- Detecting unused/dangling images accumulating over time
- Monitoring image layer deduplication efficiency
- Planning maintenance windows for image garbage collection

The script analyzes:
- Dangling images (no tags, not referenced by containers)
- Unused images (not used by any container, running or stopped)
- Build cache usage (Docker buildx cache)
- Image age and last-used timestamps where available

Exit codes:
    0 - Storage healthy, no immediate cleanup needed
    1 - Cleanup recommended (exceeds thresholds)
    2 - Usage error or no container runtime found
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime


def run_command(cmd, timeout=60):
    """Execute shell command and return result.

    Args:
        cmd: Command as list
        timeout: Timeout in seconds

    Returns:
        tuple: (return_code, stdout, stderr)
    """
    try:
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

    if check_tool_available('docker'):
        # Verify docker daemon is accessible
        rc, _, _ = run_command(['docker', 'info'], timeout=10)
        if rc == 0:
            runtimes.append('docker')

    if check_tool_available('podman'):
        # Podman works without daemon
        rc, _, _ = run_command(['podman', 'version'], timeout=10)
        if rc == 0:
            runtimes.append('podman')

    if check_tool_available('ctr'):
        # containerd via ctr
        runtimes.append('containerd')

    return runtimes


def format_bytes(bytes_val):
    """Format bytes to human-readable size."""
    if bytes_val is None:
        return "N/A"
    for unit, divisor in [('TB', 1024**4), ('GB', 1024**3),
                          ('MB', 1024**2), ('KB', 1024)]:
        if bytes_val >= divisor:
            return f"{bytes_val / divisor:.1f}{unit}"
    return f"{bytes_val}B"


def parse_docker_size(size_str):
    """Parse Docker size string (e.g., '1.5GB') to bytes."""
    if not size_str:
        return 0
    size_str = size_str.strip().upper()

    multipliers = {
        'B': 1,
        'KB': 1024,
        'MB': 1024**2,
        'GB': 1024**3,
        'TB': 1024**4,
        'KIB': 1024,
        'MIB': 1024**2,
        'GIB': 1024**3,
        'TIB': 1024**4,
    }

    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if size_str.endswith(suffix):
            try:
                num = float(size_str[:-len(suffix)])
                return int(num * mult)
            except ValueError:
                return 0
    try:
        return int(float(size_str))
    except ValueError:
        return 0


def analyze_docker_images():
    """Analyze Docker image storage.

    Returns:
        dict: Image analysis results
    """
    result = {
        'runtime': 'docker',
        'available': True,
        'total_images': 0,
        'total_size_bytes': 0,
        'dangling_count': 0,
        'dangling_size_bytes': 0,
        'unused_count': 0,
        'unused_size_bytes': 0,
        'build_cache_size_bytes': 0,
        'reclaimable_bytes': 0,
        'images': [],
        'issues': []
    }

    # Get all images with size info
    rc, stdout, stderr = run_command([
        'docker', 'images', '--format',
        '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}'
    ])

    if rc != 0:
        result['available'] = False
        result['issues'].append({
            'severity': 'CRITICAL',
            'message': f'Cannot query Docker images: {stderr.strip()}'
        })
        return result

    images_by_id = {}
    for line in stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) >= 4:
            img_id = parts[0][:12]
            repo = parts[1]
            tag = parts[2]
            size_str = parts[3]
            created = parts[4] if len(parts) > 4 else ''

            size_bytes = parse_docker_size(size_str)

            if img_id not in images_by_id:
                images_by_id[img_id] = {
                    'id': img_id,
                    'repository': repo,
                    'tag': tag,
                    'size_bytes': size_bytes,
                    'size_human': size_str,
                    'created': created,
                    'dangling': repo == '<none>',
                    'in_use': False
                }

    result['total_images'] = len(images_by_id)
    result['total_size_bytes'] = sum(img['size_bytes'] for img in images_by_id.values())

    # Get dangling images specifically
    rc, stdout, _ = run_command([
        'docker', 'images', '-f', 'dangling=true', '--format', '{{.ID}}\t{{.Size}}'
    ])

    if rc == 0:
        for line in stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                result['dangling_count'] += 1
                result['dangling_size_bytes'] += parse_docker_size(parts[1])

    # Get images used by containers (running or stopped)
    rc, stdout, _ = run_command([
        'docker', 'ps', '-a', '--format', '{{.Image}}'
    ])

    used_images = set()
    if rc == 0:
        for line in stdout.strip().split('\n'):
            if line:
                used_images.add(line)

    # Mark images in use and calculate unused
    for img_id, img in images_by_id.items():
        # Check if image or its repo:tag is in use
        repo_tag = f"{img['repository']}:{img['tag']}"
        if img_id in used_images or repo_tag in used_images or img['repository'] in used_images:
            img['in_use'] = True
        else:
            if not img['dangling']:
                result['unused_count'] += 1
                result['unused_size_bytes'] += img['size_bytes']

    result['images'] = list(images_by_id.values())

    # Get build cache info (Docker buildx)
    rc, stdout, _ = run_command(['docker', 'system', 'df', '--format', '{{json .}}'])

    if rc == 0:
        for line in stdout.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get('Type') == 'Build Cache':
                    result['build_cache_size_bytes'] = parse_docker_size(
                        data.get('Size', '0B')
                    )
            except json.JSONDecodeError:
                pass

    # Calculate total reclaimable (dangling + build cache)
    result['reclaimable_bytes'] = (
        result['dangling_size_bytes'] +
        result['build_cache_size_bytes']
    )

    # Generate issues
    if result['dangling_count'] > 0:
        severity = 'WARNING' if result['dangling_count'] > 10 else 'INFO'
        result['issues'].append({
            'severity': severity,
            'message': f"{result['dangling_count']} dangling images "
                      f"({format_bytes(result['dangling_size_bytes'])} reclaimable)"
        })

    if result['unused_count'] > 20:
        result['issues'].append({
            'severity': 'INFO',
            'message': f"{result['unused_count']} unused images "
                      f"({format_bytes(result['unused_size_bytes'])})"
        })

    if result['build_cache_size_bytes'] > 5 * 1024**3:  # > 5GB
        result['issues'].append({
            'severity': 'WARNING',
            'message': f"Build cache is {format_bytes(result['build_cache_size_bytes'])}"
        })

    return result


def analyze_podman_images():
    """Analyze Podman image storage.

    Returns:
        dict: Image analysis results
    """
    result = {
        'runtime': 'podman',
        'available': True,
        'total_images': 0,
        'total_size_bytes': 0,
        'dangling_count': 0,
        'dangling_size_bytes': 0,
        'unused_count': 0,
        'unused_size_bytes': 0,
        'reclaimable_bytes': 0,
        'images': [],
        'issues': []
    }

    # Get all images
    rc, stdout, stderr = run_command([
        'podman', 'images', '--format',
        '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.Created}}'
    ])

    if rc != 0:
        result['available'] = False
        result['issues'].append({
            'severity': 'CRITICAL',
            'message': f'Cannot query Podman images: {stderr.strip()}'
        })
        return result

    images_by_id = {}
    for line in stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) >= 4:
            img_id = parts[0][:12]
            repo = parts[1]
            tag = parts[2]
            size_str = parts[3]
            created = parts[4] if len(parts) > 4 else ''

            size_bytes = parse_docker_size(size_str)

            if img_id not in images_by_id:
                images_by_id[img_id] = {
                    'id': img_id,
                    'repository': repo,
                    'tag': tag,
                    'size_bytes': size_bytes,
                    'size_human': size_str,
                    'created': created,
                    'dangling': repo == '<none>',
                    'in_use': False
                }

    result['total_images'] = len(images_by_id)
    result['total_size_bytes'] = sum(img['size_bytes'] for img in images_by_id.values())

    # Get dangling images
    rc, stdout, _ = run_command([
        'podman', 'images', '-f', 'dangling=true', '--format', '{{.ID}}\t{{.Size}}'
    ])

    if rc == 0:
        for line in stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                result['dangling_count'] += 1
                result['dangling_size_bytes'] += parse_docker_size(parts[1])

    # Get images used by containers
    rc, stdout, _ = run_command([
        'podman', 'ps', '-a', '--format', '{{.Image}}'
    ])

    used_images = set()
    if rc == 0:
        for line in stdout.strip().split('\n'):
            if line:
                used_images.add(line)

    for img_id, img in images_by_id.items():
        repo_tag = f"{img['repository']}:{img['tag']}"
        if img_id in used_images or repo_tag in used_images or img['repository'] in used_images:
            img['in_use'] = True
        else:
            if not img['dangling']:
                result['unused_count'] += 1
                result['unused_size_bytes'] += img['size_bytes']

    result['images'] = list(images_by_id.values())
    result['reclaimable_bytes'] = result['dangling_size_bytes']

    # Generate issues
    if result['dangling_count'] > 0:
        severity = 'WARNING' if result['dangling_count'] > 10 else 'INFO'
        result['issues'].append({
            'severity': severity,
            'message': f"{result['dangling_count']} dangling images "
                      f"({format_bytes(result['dangling_size_bytes'])} reclaimable)"
        })

    if result['unused_count'] > 20:
        result['issues'].append({
            'severity': 'INFO',
            'message': f"{result['unused_count']} unused images "
                      f"({format_bytes(result['unused_size_bytes'])})"
        })

    return result


def analyze_containerd_images():
    """Analyze containerd image storage.

    Returns:
        dict: Image analysis results
    """
    result = {
        'runtime': 'containerd',
        'available': True,
        'total_images': 0,
        'total_size_bytes': 0,
        'reclaimable_bytes': 0,
        'images': [],
        'issues': []
    }

    # ctr requires namespace specification
    rc, stdout, stderr = run_command([
        'ctr', '-n', 'k8s.io', 'images', 'ls', '-q'
    ])

    if rc != 0:
        # Try default namespace
        rc, stdout, stderr = run_command([
            'ctr', 'images', 'ls', '-q'
        ])

    if rc != 0:
        result['available'] = False
        result['issues'].append({
            'severity': 'WARNING',
            'message': f'Cannot query containerd images: {stderr.strip()}'
        })
        return result

    images = [img for img in stdout.strip().split('\n') if img]
    result['total_images'] = len(images)

    # Note: ctr doesn't provide easy size info without more complex queries
    # We'll report what we can

    if result['total_images'] > 0:
        result['images'] = [{'id': img, 'repository': img} for img in images[:50]]

    return result


def get_storage_path_usage(runtime):
    """Get disk usage for container storage paths.

    Args:
        runtime: Container runtime name

    Returns:
        dict: Storage path information or None
    """
    paths = {
        'docker': ['/var/lib/docker'],
        'podman': ['/var/lib/containers/storage',
                   os.path.expanduser('~/.local/share/containers')],
        'containerd': ['/var/lib/containerd']
    }

    for path in paths.get(runtime, []):
        if os.path.exists(path):
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
            except OSError:
                continue
    return None


def output_plain(results, verbose, warn_only, storage_warn_pct):
    """Output results in plain text format."""
    lines = []

    has_any_issues = any(
        any(i['severity'] in ['CRITICAL', 'WARNING'] for i in r.get('issues', []))
        for r in results
    )

    for r in results:
        runtime = r['runtime']
        issues = r.get('issues', [])
        storage = r.get('storage')

        # Skip if no issues and warn_only
        if warn_only and not any(i['severity'] in ['CRITICAL', 'WARNING'] for i in issues):
            if not storage or storage['usage_percent'] < storage_warn_pct:
                continue

        lines.append(f"=== {runtime.upper()} IMAGE ANALYSIS ===")

        if not r.get('available'):
            lines.append("Status: Not available")
            for issue in issues:
                lines.append(f"  [{issue['severity']}] {issue['message']}")
            lines.append("")
            continue

        lines.append(f"Total images: {r['total_images']}")

        if r['total_size_bytes'] > 0:
            lines.append(f"Total size: {format_bytes(r['total_size_bytes'])}")

        if r['dangling_count'] > 0 or verbose:
            lines.append(f"Dangling images: {r.get('dangling_count', 0)} "
                        f"({format_bytes(r.get('dangling_size_bytes', 0))})")

        if r.get('unused_count', 0) > 0 or verbose:
            lines.append(f"Unused images: {r.get('unused_count', 0)} "
                        f"({format_bytes(r.get('unused_size_bytes', 0))})")

        if r.get('build_cache_size_bytes', 0) > 0 or verbose:
            lines.append(f"Build cache: {format_bytes(r.get('build_cache_size_bytes', 0))}")

        if r['reclaimable_bytes'] > 0:
            lines.append(f"Reclaimable: {format_bytes(r['reclaimable_bytes'])}")

        # Storage path info
        if storage:
            lines.append(f"Storage path: {storage['path']}")
            lines.append(f"  Disk usage: {storage['usage_percent']:.1f}% "
                        f"({format_bytes(storage['free_bytes'])} free)")

            if storage['usage_percent'] >= storage_warn_pct:
                lines.append(f"  [WARNING] Storage usage exceeds {storage_warn_pct}%")

        # Issues
        for issue in issues:
            if warn_only and issue['severity'] == 'INFO':
                continue
            lines.append(f"[{issue['severity']}] {issue['message']}")

        # Verbose image list
        if verbose and r.get('images'):
            lines.append("")
            lines.append("Image details:")
            shown = 0
            for img in r['images']:
                if img.get('dangling') or not img.get('in_use', True):
                    status = "dangling" if img.get('dangling') else "unused"
                    lines.append(f"  {img['id']} {img.get('repository', 'N/A')}:"
                                f"{img.get('tag', 'N/A')} [{status}] "
                                f"{format_bytes(img.get('size_bytes', 0))}")
                    shown += 1
                    if shown >= 20:
                        remaining = len([i for i in r['images']
                                        if i.get('dangling') or not i.get('in_use', True)]) - shown
                        if remaining > 0:
                            lines.append(f"  ... and {remaining} more")
                        break

        lines.append("")

    # Summary
    if not warn_only or has_any_issues:
        total_reclaimable = sum(r.get('reclaimable_bytes', 0) for r in results)
        if total_reclaimable > 0:
            lines.append(f"Total reclaimable across all runtimes: {format_bytes(total_reclaimable)}")
            lines.append("")
            lines.append("To clean up:")
            for r in results:
                if r['runtime'] == 'docker' and r.get('reclaimable_bytes', 0) > 0:
                    lines.append("  docker system prune -f  # Remove dangling images and build cache")
                    lines.append("  docker image prune -a   # Also remove unused images")
                elif r['runtime'] == 'podman' and r.get('reclaimable_bytes', 0) > 0:
                    lines.append("  podman system prune -f  # Remove dangling images")
                    lines.append("  podman image prune -a   # Also remove unused images")
        elif not has_any_issues:
            lines.append("No cleanup needed - storage is healthy.")

    return '\n'.join(lines)


def output_json(results):
    """Output results in JSON format."""
    total_images = sum(r.get('total_images', 0) for r in results)
    total_size = sum(r.get('total_size_bytes', 0) for r in results)
    total_reclaimable = sum(r.get('reclaimable_bytes', 0) for r in results)
    total_dangling = sum(r.get('dangling_count', 0) for r in results)

    output = {
        'timestamp': datetime.now().isoformat(),
        'runtimes': results,
        'summary': {
            'total_runtimes': len(results),
            'total_images': total_images,
            'total_size_bytes': total_size,
            'total_reclaimable_bytes': total_reclaimable,
            'total_dangling_images': total_dangling,
            'cleanup_recommended': total_reclaimable > 1024**3 or total_dangling > 10
        }
    }
    return json.dumps(output, indent=2)


def output_table(results, warn_only, storage_warn_pct):
    """Output results in table format."""
    lines = []

    lines.append("=" * 85)
    lines.append("CONTAINER IMAGE CLEANUP ANALYSIS")
    lines.append("=" * 85)
    lines.append(f"{'Runtime':<12} {'Images':<8} {'Total':<10} {'Dangling':<10} "
                f"{'Unused':<10} {'Reclaimable':<12} {'Disk%':<8}")
    lines.append("-" * 85)

    for r in results:
        if not r.get('available'):
            lines.append(f"{r['runtime']:<12} {'N/A':<8} {'N/A':<10} {'N/A':<10} "
                        f"{'N/A':<10} {'N/A':<12} {'N/A':<8}")
            continue

        storage = r.get('storage', {})
        disk_pct = f"{storage.get('usage_percent', 0):.0f}%" if storage else "N/A"

        lines.append(
            f"{r['runtime']:<12} "
            f"{r['total_images']:<8} "
            f"{format_bytes(r.get('total_size_bytes', 0)):<10} "
            f"{r.get('dangling_count', 0):<10} "
            f"{r.get('unused_count', 0):<10} "
            f"{format_bytes(r.get('reclaimable_bytes', 0)):<12} "
            f"{disk_pct:<8}"
        )

    lines.append("=" * 85)

    # Collect all issues
    all_issues = []
    for r in results:
        for issue in r.get('issues', []):
            if warn_only and issue['severity'] == 'INFO':
                continue
            all_issues.append((r['runtime'], issue))

        storage = r.get('storage')
        if storage and storage['usage_percent'] >= storage_warn_pct:
            all_issues.append((r['runtime'], {
                'severity': 'WARNING',
                'message': f"Storage at {storage['usage_percent']:.1f}%"
            }))

    if all_issues:
        lines.append("")
        lines.append("ISSUES:")
        for runtime, issue in all_issues:
            lines.append(f"  [{issue['severity']}] {runtime}: {issue['message']}")

    return '\n'.join(lines)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Analyze container image storage and cleanup needs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                        # Analyze all detected runtimes
  %(prog)s --runtime docker       # Analyze Docker only
  %(prog)s --format json          # JSON output for monitoring
  %(prog)s --verbose              # Show individual image details
  %(prog)s --storage-warn 80      # Warn when disk usage exceeds 80%%

Cleanup commands:
  docker system prune -f          # Remove dangling images and build cache
  docker image prune -a           # Remove all unused images
  podman system prune -f          # Remove dangling images
  podman image prune -a           # Remove all unused images

Exit codes:
  0 - Storage healthy, no immediate cleanup needed
  1 - Cleanup recommended (dangling images, high disk usage)
  2 - Usage error or no container runtime found
        """
    )

    parser.add_argument(
        '--runtime',
        choices=['docker', 'podman', 'containerd'],
        action='append',
        help='Specific runtime(s) to analyze (default: auto-detect)'
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
        help='Show detailed image information'
    )

    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings and issues'
    )

    parser.add_argument(
        '--storage-warn',
        type=float,
        default=85.0,
        metavar='PCT',
        help='Disk usage warning threshold (default: 85%%)'
    )

    parser.add_argument(
        '--dangling-warn',
        type=int,
        default=10,
        metavar='COUNT',
        help='Dangling image count warning threshold (default: 10)'
    )

    parser.add_argument(
        '--reclaimable-warn',
        type=float,
        default=5.0,
        metavar='GB',
        help='Reclaimable space warning threshold in GB (default: 5)'
    )

    args = parser.parse_args()

    # Validate args
    if args.storage_warn < 0 or args.storage_warn > 100:
        print("Error: --storage-warn must be between 0 and 100", file=sys.stderr)
        sys.exit(2)

    if args.dangling_warn < 0:
        print("Error: --dangling-warn must be non-negative", file=sys.stderr)
        sys.exit(2)

    if args.reclaimable_warn < 0:
        print("Error: --reclaimable-warn must be non-negative", file=sys.stderr)
        sys.exit(2)

    reclaimable_warn_bytes = args.reclaimable_warn * 1024**3

    # Detect or use specified runtimes
    if args.runtime:
        runtimes = args.runtime
    else:
        runtimes = detect_runtimes()

    if not runtimes:
        print("Error: No container runtimes detected", file=sys.stderr)
        print("Install one of: docker, podman, containerd (ctr)", file=sys.stderr)
        sys.exit(2)

    # Analyze each runtime
    results = []
    for runtime in runtimes:
        if runtime == 'docker':
            result = analyze_docker_images()
        elif runtime == 'podman':
            result = analyze_podman_images()
        elif runtime == 'containerd':
            result = analyze_containerd_images()
        else:
            continue

        # Add storage path info
        result['storage'] = get_storage_path_usage(runtime)

        # Add threshold-based issues
        if result.get('reclaimable_bytes', 0) >= reclaimable_warn_bytes:
            result.setdefault('issues', []).append({
                'severity': 'WARNING',
                'message': f"Reclaimable space exceeds {args.reclaimable_warn}GB threshold"
            })

        results.append(result)

    # Output results
    if args.format == 'json':
        print(output_json(results))
    elif args.format == 'table':
        print(output_table(results, args.warn_only, args.storage_warn))
    else:
        print(output_plain(results, args.verbose, args.warn_only, args.storage_warn))

    # Determine exit code
    has_warnings = False
    for r in results:
        # Check for explicit issues
        if any(i['severity'] in ['CRITICAL', 'WARNING'] for i in r.get('issues', [])):
            has_warnings = True

        # Check storage threshold
        storage = r.get('storage')
        if storage and storage['usage_percent'] >= args.storage_warn:
            has_warnings = True

        # Check reclaimable threshold
        if r.get('reclaimable_bytes', 0) >= reclaimable_warn_bytes:
            has_warnings = True

        # Check dangling threshold
        if r.get('dangling_count', 0) >= args.dangling_warn:
            has_warnings = True

    sys.exit(1 if has_warnings else 0)


if __name__ == '__main__':
    main()
