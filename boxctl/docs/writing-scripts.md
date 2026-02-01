# Writing Scripts

Guide for adding new diagnostic scripts to boxctl.

## Script Structure

Every script follows the same pattern:

```python
#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_space_forecaster]
#   brief: Check disk health using SMART attributes

"""
Full description of what this script does.

Explains the problem it solves and how to interpret results.
"""

import argparse
from boxctl.core.context import Context
from boxctl.core.output import Output


def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments
        output: Output helper for structured data
        context: Execution context (mockable for tests)

    Returns:
        0 = healthy, 1 = issues found, 2 = error
    """
    parser = argparse.ArgumentParser(description='...')
    # Add arguments...
    opts = parser.parse_args(args)

    # Check required tools
    if not context.check_tool('smartctl'):
        output.error('smartctl not found')
        return 2

    # Do work using context for external calls
    result = context.run(['smartctl', '-a', '/dev/sda'])

    # Emit structured data
    output.emit({
        'status': 'healthy',
        'devices': [...]
    })

    # Set summary
    output.set_summary('3 devices checked, all healthy')

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1:], Output(), Context()))
```

## Metadata Header

The metadata header is a YAML block in comments at the top of the file.

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `category` | string | Script category in `parent/child` format |
| `tags` | list | Keywords for search and filtering |
| `brief` | string | One-line description (shown in `boxctl list`) |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `requires` | list | External tools needed (e.g., `[smartctl, nvme]`) |
| `privilege` | string | `root` if sudo required, `user` otherwise |
| `related` | list | Names of related scripts |

### Example Headers

```python
# Baremetal disk script
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage, hardware]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_space_forecaster, disk_io_latency_monitor]
#   brief: Check disk health using SMART attributes
```

```python
# Kubernetes pod script
# boxctl:
#   category: k8s/pods
#   tags: [pods, resources, scheduling]
#   requires: [kubectl]
#   privilege: user
#   related: [pending_pod_debugger, node_capacity]
#   brief: Analyze pod resource requests and limits
```

### Valid Categories

**Baremetal:**
- `baremetal/disk` - Disk health, space, I/O
- `baremetal/memory` - Memory pressure, OOM, leaks
- `baremetal/cpu` - CPU steal, scheduling, topology
- `baremetal/network` - Network connections, packets, interfaces
- `baremetal/process` - Process monitoring, zombies, ancestry
- `baremetal/security` - Audits, setuid, permissions
- `baremetal/kernel` - Kernel parameters, modules
- `baremetal/systemd` - Service health, dependencies

**Kubernetes:**
- `k8s/pods` - Pod analysis, debugging
- `k8s/nodes` - Node capacity, health
- `k8s/resources` - Quotas, limits, requests
- `k8s/network` - Network policies, services
- `k8s/events` - Cluster events, logs

## The Context API

`Context` wraps external dependencies for testability.

### Methods

```python
# Check if tool exists
context.check_tool('kubectl')  # -> bool

# Run command
result = context.run(['kubectl', 'get', 'pods', '-o', 'json'])
result.stdout  # Command output
result.stderr  # Error output
result.returncode  # Exit code

# Run with options
context.run(cmd, check=True)  # Raise on error
context.run(cmd, timeout=30)  # Custom timeout

# File operations
context.read_file('/proc/meminfo')  # -> str
context.file_exists('/etc/foo')  # -> bool
context.glob('*.conf', root='/etc')  # -> list[str]

# Environment
context.get_env('HOME')  # -> str | None
context.cpu_count()  # -> int
```

### Why Use Context?

**Without context (hard to test):**
```python
import subprocess
result = subprocess.run(['kubectl', 'get', 'pods'], ...)
```

**With context (testable):**
```python
def run(args, output, context):
    result = context.run(['kubectl', 'get', 'pods'])
```

In tests, you can inject `MockContext` with predefined outputs.

## The Output API

`Output` collects structured data from your script.

### Methods

```python
# Store structured data
output.emit({
    'status': 'healthy',
    'devices': [...],
    'metrics': {...}
})

# Record errors
output.error('smartctl not found')

# Record warnings
output.warning('Device /dev/sdc showing wear')

# Set one-line summary
output.set_summary('3 devices checked, 1 warning')
```

### Accessing Data

```python
output.data       # dict of emitted data
output.errors     # list of error messages
output.warnings   # list of warning messages
output.summary    # summary string
output.to_json()  # JSON representation
output.to_plain() # Plain text representation
```

## Exit Codes

Scripts must return one of these codes:

| Code | Meaning | When to Use |
|------|---------|-------------|
| 0 | Success / healthy | No issues found |
| 1 | Issues found | Warnings, errors, or problems detected |
| 2 | Script error | Bad arguments, missing tools, runtime error |

**Example:**
```python
def run(args, output, context):
    if not context.check_tool('kubectl'):
        output.error('kubectl not found')
        return 2  # Script can't run

    # ... do analysis ...

    if unhealthy_pods:
        output.warning(f'{len(unhealthy_pods)} unhealthy pods')
        return 1  # Issues found

    return 0  # All healthy
```

## Testing Scripts

Tests use `MockContext` to simulate external dependencies.

### Basic Test

```python
import pytest
from boxctl.core.output import Output

class TestDiskHealth:
    def test_missing_tool_returns_error(self, mock_context):
        from scripts.baremetal import disk_health

        ctx = mock_context(tools_available=[])  # No tools
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 2
        assert 'smartctl' in output.errors[0].lower()

    def test_healthy_disk(self, mock_context, fixtures_dir):
        from scripts.baremetal import disk_health

        smartctl_output = (fixtures_dir / 'disk' / 'smart_healthy.txt').read_text()

        ctx = mock_context(
            tools_available=['smartctl'],
            command_outputs={
                ('smartctl', '-a', '/dev/sda'): smartctl_output,
            }
        )
        output = Output()

        exit_code = disk_health.run(['--device', '/dev/sda'], output, ctx)

        assert exit_code == 0
        assert output.data['status'] == 'healthy'
```

### MockContext Options

```python
mock_context(
    # Tools that exist in PATH
    tools_available=['kubectl', 'smartctl'],

    # Command outputs (tuple of args -> output string)
    command_outputs={
        ('kubectl', 'get', 'pods', '-o', 'json'): '{"items": [...]}',
        ('smartctl', '-a', '/dev/sda'): 'SMART data...',
    },

    # File contents for read_file()
    file_contents={
        '/proc/meminfo': 'MemTotal: 16000000 kB\n...',
        '/etc/os-release': 'ID=ubuntu\n...',
    },

    # Environment variables
    env={
        'HOME': '/home/user',
        'cpu_count': '8',
    },
)
```

### Test Fixtures

Store test data in `tests/fixtures/<category>/`:

```
tests/fixtures/
  disk/
    smart_healthy.txt
    smart_failing.txt
  k8s/
    pods_healthy.json
    pods_pending.json
```

Load fixtures:
```python
def test_something(self, fixtures_dir):
    data = (fixtures_dir / 'k8s' / 'pods_healthy.json').read_text()
```

## Argument Parsing

Use argparse with common patterns:

```python
def run(args, output, context):
    parser = argparse.ArgumentParser(
        description='Analyze disk health'
    )

    # Common options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '-w', '--warn-only',
        action='store_true',
        help='Only show warnings/errors'
    )
    parser.add_argument(
        '--format',
        choices=['plain', 'json'],
        default='plain',
        help='Output format'
    )

    # Script-specific options
    parser.add_argument(
        '--device',
        help='Specific device to check'
    )
    parser.add_argument(
        '-n', '--namespace',
        help='Kubernetes namespace'
    )

    opts = parser.parse_args(args)
```

## Best Practices

1. **Check tools early** - Return exit code 2 immediately if required tools are missing

2. **Use context for all external calls** - Never use `subprocess.run()` directly

3. **Emit structured data** - Use `output.emit()` for data that can be JSON-serialized

4. **Set meaningful summaries** - `output.set_summary()` should be a one-liner

5. **Handle errors gracefully** - Catch exceptions, record with `output.error()`, return 2

6. **Write comprehensive tests** - Test error cases, edge cases, and happy path

7. **Keep scripts focused** - One script does one thing well

## Checklist

Before submitting a new script:

- [ ] Metadata header has all required fields
- [ ] Category is in valid `parent/child` format
- [ ] Script is executable (`chmod +x`)
- [ ] Uses `Context` for all external calls
- [ ] Uses `Output` for structured data
- [ ] Returns correct exit codes
- [ ] Has comprehensive tests
- [ ] `boxctl lint` passes
- [ ] `boxctl doctor` shows no issues for this script

## See Also

- [CLI Reference](cli-reference.md) - Command documentation
- [Architecture](architecture.md) - System design overview
