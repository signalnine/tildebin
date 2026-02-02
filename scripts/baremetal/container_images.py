#!/usr/bin/env python3
# boxctl:
#   category: baremetal/container
#   tags: [container, docker, podman, cleanup, storage]
#   requires: []
#   privilege: none
#   related: [disk_space_forecaster, disk_health]
#   brief: Analyze container image storage and cleanup needs

"""
Analyze container image storage and cleanup needs on baremetal systems.

Examines container image storage usage across Docker, containerd, and Podman
runtimes to identify cleanup opportunities and predict when garbage collection
should be performed.

Useful for:
- Identifying hosts that need image cleanup before disk pressure
- Estimating space that can be recovered by running image prune
- Detecting unused/dangling images accumulating over time
- Monitoring image layer deduplication efficiency
- Planning maintenance windows for image garbage collection

The script analyzes:
- Dangling images (no tags, not referenced by containers)
- Unused images (not used by any container)
- Build cache usage (Docker buildx cache)
"""

import argparse
import json
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


def format_bytes(bytes_val: int | None) -> str:
    """Format bytes to human-readable size."""
    if bytes_val is None:
        return "N/A"
    for unit, divisor in [('TB', 1024**4), ('GB', 1024**3),
                          ('MB', 1024**2), ('KB', 1024)]:
        if bytes_val >= divisor:
            return f"{bytes_val / divisor:.1f}{unit}"
    return f"{bytes_val}B"


def parse_docker_size(size_str: str) -> int:
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


def detect_runtimes(context: Context) -> list[str]:
    """Detect which container runtimes are installed."""
    runtimes = []

    if context.check_tool('docker'):
        result = context.run(['docker', 'info'], check=False)
        if result.returncode == 0:
            runtimes.append('docker')

    if context.check_tool('podman'):
        result = context.run(['podman', 'version'], check=False)
        if result.returncode == 0:
            runtimes.append('podman')

    if context.check_tool('ctr'):
        runtimes.append('containerd')

    return runtimes


def analyze_docker_images(context: Context) -> dict[str, Any]:
    """Analyze Docker image storage."""
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
        'issues': []
    }

    # Get all images with size info
    cmd_result = context.run([
        'docker', 'images', '--format',
        '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}'
    ], check=False)

    if cmd_result.returncode != 0:
        result['available'] = False
        result['issues'].append({
            'severity': 'critical',
            'message': f'Cannot query Docker images: {cmd_result.stderr.strip()}'
        })
        return result

    images_by_id = {}
    for line in cmd_result.stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) >= 4:
            img_id = parts[0][:12]
            repo = parts[1]
            tag = parts[2]
            size_str = parts[3]

            size_bytes = parse_docker_size(size_str)

            if img_id not in images_by_id:
                images_by_id[img_id] = {
                    'id': img_id,
                    'repository': repo,
                    'tag': tag,
                    'size_bytes': size_bytes,
                    'dangling': repo == '<none>',
                    'in_use': False
                }

    result['total_images'] = len(images_by_id)
    result['total_size_bytes'] = sum(img['size_bytes'] for img in images_by_id.values())

    # Get dangling images
    cmd_result = context.run([
        'docker', 'images', '-f', 'dangling=true', '--format', '{{.ID}}\t{{.Size}}'
    ], check=False)

    if cmd_result.returncode == 0:
        for line in cmd_result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                result['dangling_count'] += 1
                result['dangling_size_bytes'] += parse_docker_size(parts[1])

    # Get images used by containers
    cmd_result = context.run(['docker', 'ps', '-a', '--format', '{{.Image}}'], check=False)

    used_images = set()
    if cmd_result.returncode == 0:
        for line in cmd_result.stdout.strip().split('\n'):
            if line:
                used_images.add(line)

    # Mark images in use and calculate unused
    for img_id, img in images_by_id.items():
        repo_tag = f"{img['repository']}:{img['tag']}"
        if img_id in used_images or repo_tag in used_images or img['repository'] in used_images:
            img['in_use'] = True
        else:
            if not img['dangling']:
                result['unused_count'] += 1
                result['unused_size_bytes'] += img['size_bytes']

    # Get build cache info
    cmd_result = context.run(['docker', 'system', 'df', '--format', '{{json .}}'], check=False)

    if cmd_result.returncode == 0:
        for line in cmd_result.stdout.strip().split('\n'):
            if not line:
                continue
            try:
                data = json.loads(line)
                if data.get('Type') == 'Build Cache':
                    result['build_cache_size_bytes'] = parse_docker_size(data.get('Size', '0B'))
            except json.JSONDecodeError:
                pass

    # Calculate total reclaimable
    result['reclaimable_bytes'] = result['dangling_size_bytes'] + result['build_cache_size_bytes']

    # Generate issues
    if result['dangling_count'] > 10:
        result['issues'].append({
            'severity': 'warning',
            'message': f"{result['dangling_count']} dangling images ({format_bytes(result['dangling_size_bytes'])} reclaimable)"
        })
    elif result['dangling_count'] > 0:
        result['issues'].append({
            'severity': 'info',
            'message': f"{result['dangling_count']} dangling images"
        })

    if result['build_cache_size_bytes'] > 5 * 1024**3:  # > 5GB
        result['issues'].append({
            'severity': 'warning',
            'message': f"Build cache is {format_bytes(result['build_cache_size_bytes'])}"
        })

    return result


def analyze_podman_images(context: Context) -> dict[str, Any]:
    """Analyze Podman image storage."""
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
        'issues': []
    }

    # Get all images
    cmd_result = context.run([
        'podman', 'images', '--format',
        '{{.ID}}\t{{.Repository}}\t{{.Tag}}\t{{.Size}}'
    ], check=False)

    if cmd_result.returncode != 0:
        result['available'] = False
        result['issues'].append({
            'severity': 'critical',
            'message': f'Cannot query Podman images: {cmd_result.stderr.strip()}'
        })
        return result

    images_by_id = {}
    for line in cmd_result.stdout.strip().split('\n'):
        if not line:
            continue
        parts = line.split('\t')
        if len(parts) >= 4:
            img_id = parts[0][:12]
            repo = parts[1]
            size_str = parts[3]

            size_bytes = parse_docker_size(size_str)

            if img_id not in images_by_id:
                images_by_id[img_id] = {
                    'id': img_id,
                    'repository': repo,
                    'size_bytes': size_bytes,
                    'dangling': repo == '<none>',
                }

    result['total_images'] = len(images_by_id)
    result['total_size_bytes'] = sum(img['size_bytes'] for img in images_by_id.values())

    # Get dangling images
    cmd_result = context.run([
        'podman', 'images', '-f', 'dangling=true', '--format', '{{.ID}}\t{{.Size}}'
    ], check=False)

    if cmd_result.returncode == 0:
        for line in cmd_result.stdout.strip().split('\n'):
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                result['dangling_count'] += 1
                result['dangling_size_bytes'] += parse_docker_size(parts[1])

    result['reclaimable_bytes'] = result['dangling_size_bytes']

    # Generate issues
    if result['dangling_count'] > 10:
        result['issues'].append({
            'severity': 'warning',
            'message': f"{result['dangling_count']} dangling images"
        })

    return result


def analyze_containerd_images(context: Context) -> dict[str, Any]:
    """Analyze containerd image storage."""
    result = {
        'runtime': 'containerd',
        'available': True,
        'total_images': 0,
        'reclaimable_bytes': 0,
        'issues': []
    }

    # Try k8s.io namespace first
    cmd_result = context.run(['ctr', '-n', 'k8s.io', 'images', 'ls', '-q'], check=False)

    if cmd_result.returncode != 0:
        # Try default namespace
        cmd_result = context.run(['ctr', 'images', 'ls', '-q'], check=False)

    if cmd_result.returncode != 0:
        result['available'] = False
        result['issues'].append({
            'severity': 'warning',
            'message': f'Cannot query containerd images: {cmd_result.stderr.strip()}'
        })
        return result

    images = [img for img in cmd_result.stdout.strip().split('\n') if img]
    result['total_images'] = len(images)

    return result


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
    parser = argparse.ArgumentParser(description="Analyze container image storage and cleanup needs")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    parser.add_argument("--runtime", choices=['docker', 'podman', 'containerd'], action='append',
                        help="Specific runtime(s) to analyze (default: auto-detect)")
    parser.add_argument("--storage-warn", type=float, default=85.0, metavar="PCT",
                        help="Disk usage warning threshold (default: 85%%)")
    parser.add_argument("--dangling-warn", type=int, default=10, metavar="COUNT",
                        help="Dangling image count warning threshold (default: 10)")
    parser.add_argument("--reclaimable-warn", type=float, default=5.0, metavar="GB",
                        help="Reclaimable space warning threshold in GB (default: 5)")
    opts = parser.parse_args(args)

    # Detect or use specified runtimes
    if opts.runtime:
        runtimes = opts.runtime
    else:
        runtimes = detect_runtimes(context)

    if not runtimes:
        output.error("No container runtimes detected (docker, podman, ctr)")
        return 2

    reclaimable_warn_bytes = opts.reclaimable_warn * 1024**3

    # Analyze each runtime
    results = []
    for runtime in runtimes:
        if runtime == 'docker':
            result = analyze_docker_images(context)
        elif runtime == 'podman':
            result = analyze_podman_images(context)
        elif runtime == 'containerd':
            result = analyze_containerd_images(context)
        else:
            continue

        # Add threshold-based issues
        if result.get('reclaimable_bytes', 0) >= reclaimable_warn_bytes:
            result.setdefault('issues', []).append({
                'severity': 'warning',
                'message': f"Reclaimable space exceeds {opts.reclaimable_warn}GB threshold"
            })

        if result.get('dangling_count', 0) >= opts.dangling_warn:
            # Check if we already have a warning for this
            has_warning = any('dangling' in i.get('message', '').lower()
                             for i in result.get('issues', []) if i.get('severity') == 'warning')
            if not has_warning:
                result.setdefault('issues', []).append({
                    'severity': 'warning',
                    'message': f"Dangling image count exceeds {opts.dangling_warn}"
                })

        results.append(result)

    # Build output
    total_images = sum(r.get('total_images', 0) for r in results)
    total_reclaimable = sum(r.get('reclaimable_bytes', 0) for r in results)
    total_dangling = sum(r.get('dangling_count', 0) for r in results)

    all_issues = []
    for r in results:
        for issue in r.get('issues', []):
            all_issues.append({
                'runtime': r['runtime'],
                **issue
            })

    output_data = {
        'runtimes': results,
        'summary': {
            'total_runtimes': len(results),
            'total_images': total_images,
            'total_reclaimable_bytes': total_reclaimable,
            'total_reclaimable_human': format_bytes(total_reclaimable),
            'total_dangling_images': total_dangling,
            'cleanup_recommended': total_reclaimable > 1024**3 or total_dangling > 10
        },
        'issues': all_issues
    }

    output.emit(output_data)

    # Set summary
    has_warnings = any(i.get('severity') in ['critical', 'warning'] for i in all_issues)
    if has_warnings:
        output.set_summary(f"{format_bytes(total_reclaimable)} reclaimable, {total_dangling} dangling")
    else:
        output.set_summary(f"{total_images} images across {len(results)} runtime(s)")

    return 1 if has_warnings else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
