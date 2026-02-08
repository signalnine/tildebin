#!/usr/bin/env python3
# boxctl:
#   category: baremetal/security
#   tags: [security, libraries, ld_preload, audit, integrity]
#   requires: []
#   privilege: root
#   related: [suid_sgid_audit, file_integrity, kernel_module_audit]
#   brief: Audit shared library configuration for hijacking risks

"""
Audit shared library configuration for hijacking risks.

Checks for LD_PRELOAD hijacking vectors, non-standard library paths, and
suspicious library configuration that could indicate system compromise.

Reads from:
- /etc/ld.so.preload for preloaded libraries
- /etc/ld.so.conf and /etc/ld.so.conf.d/*.conf for library search paths

Exit codes:
    0 - Clean configuration
    1 - Suspicious configuration detected
    2 - Error or missing dependencies
"""

import argparse
from typing import Any

from boxctl.core.context import Context
from boxctl.core.output import Output


STANDARD_LIB_PREFIXES = (
    '/lib',
    '/usr/lib',
    '/usr/local/lib',
)


def parse_preload(content: str) -> list[str]:
    """Parse /etc/ld.so.preload for library entries.

    Returns list of non-empty, non-comment library paths.
    """
    entries = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#'):
            entries.append(line)
    return entries


def parse_ld_conf(content: str) -> list[str]:
    """Parse ld.so.conf or ld.so.conf.d/*.conf for library paths.

    Returns list of library paths (ignores 'include' directives and comments).
    """
    paths = []
    for line in content.split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('include'):
            continue
        paths.append(line)
    return paths


def analyze_paths(paths: list[str]) -> list[dict[str, Any]]:
    """Analyze library paths for non-standard entries.

    Returns list of INFO issues for non-standard paths.
    """
    issues = []
    for path in paths:
        if not any(path.startswith(prefix) for prefix in STANDARD_LIB_PREFIXES):
            issues.append({
                'severity': 'INFO',
                'type': 'non_standard_path',
                'path': path,
                'message': f"Non-standard library path: {path}",
            })
    return issues


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper
        context: Execution context

    Returns:
        0 = clean, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(
        description="Audit shared library configuration for hijacking risks"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Show all library paths")
    parser.add_argument("--format", choices=["plain", "json"], default="plain")
    opts = parser.parse_args(args)

    # Check ld.so.conf exists
    if not context.file_exists('/etc/ld.so.conf'):
        output.error("/etc/ld.so.conf not found")
        output.render(opts.format, "Shared Library Audit")
        return 2

    issues: list[dict[str, Any]] = []

    # Check /etc/ld.so.preload
    preload_entries: list[str] = []
    if context.file_exists('/etc/ld.so.preload'):
        try:
            preload_content = context.read_file('/etc/ld.so.preload')
            preload_entries = parse_preload(preload_content)
            if preload_entries:
                issues.append({
                    'severity': 'WARNING',
                    'type': 'preload_entries',
                    'entries': preload_entries,
                    'message': (
                        f"/etc/ld.so.preload contains {len(preload_entries)} "
                        f"entries: {', '.join(preload_entries)}"
                    ),
                })
        except Exception:
            pass

    # Read library paths from ld.so.conf
    all_paths: list[str] = []
    config_files: list[str] = []

    try:
        conf_content = context.read_file('/etc/ld.so.conf')
        paths = parse_ld_conf(conf_content)
        all_paths.extend(paths)
        config_files.append('/etc/ld.so.conf')
    except Exception:
        pass

    # Read ld.so.conf.d/*.conf files
    conf_d_files = context.glob('*.conf', '/etc/ld.so.conf.d')
    for conf_file in sorted(conf_d_files):
        try:
            content = context.read_file(conf_file)
            paths = parse_ld_conf(content)
            all_paths.extend(paths)
            config_files.append(conf_file)
        except Exception:
            pass

    # Analyze paths
    path_issues = analyze_paths(all_paths)
    issues.extend(path_issues)

    # Emit data
    data: dict[str, Any] = {
        'preload_entries': preload_entries,
        'library_paths': all_paths,
        'config_files': config_files,
        'issues': issues,
    }

    output.emit(data)

    # Summary
    warning_count = sum(1 for i in issues if i['severity'] == 'WARNING')
    if warning_count > 0:
        output.set_summary(f"{warning_count} warnings, {len(all_paths)} library paths")
    else:
        output.set_summary(f"clean, {len(all_paths)} library paths")

    output.render(opts.format, "Shared Library Audit")

    has_issues = any(i['severity'] in ('CRITICAL', 'WARNING') for i in issues)
    return 1 if has_issues else 0


if __name__ == "__main__":
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
