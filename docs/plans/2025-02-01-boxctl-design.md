# boxctl Design Document

A unified CLI for discovering, running, and monitoring baremetal and Kubernetes utility scripts. Bundled Python runtime with ~200 external scripts.

## Overview

**Problem**: 200+ standalone utility scripts with no unified discovery, orchestration, or monitoring. Inconsistent Python versions across hosts.

**Solution**: `boxctl` - a self-contained distribution that includes:
- Portable Python runtime (no system Python dependency)
- The orchestration CLI framework
- All baremetal_* and k8s_* scripts as separate files (independently updatable)
- Built-in profiles and runbooks

**Target Users**: Team of sysadmins who need approachable tooling with sensible defaults.

## Core Concepts

| Concept | Description |
|---------|-------------|
| **Scripts** | Python files with header metadata and standard `run(args, output) -> int` interface |
| **Tags** | Flexible labels for grouping (disk, health, security, network, pod, node) |
| **Categories** | Two domains: `baremetal/*` and `k8s/*` with subsystem hierarchy |
| **Profiles** | Named bundles for server roles (k8s-worker, database-server) |
| **Runbooks** | YAML workflows with conditional logic and parallel execution |
| **Smart Groups** | Ad-hoc queries by tag/category |

## Architecture

### Bundled Runtime + External Scripts

Scripts are separate files invoked by the bundled Python runtime:

```
boxctl run disk_health
    → /opt/boxctl/runtime/bin/python /opt/boxctl/scripts/baremetal/disk_health.py
```

Key benefits:
- No system Python dependency
- Scripts can be hotfixed without rebuilding
- User overrides take precedence over bundled scripts

### Installation Layout

```
/opt/boxctl/                        # System installation
├── bin/
│   └── boxctl                      # Wrapper script (bash)
├── runtime/                        # python-build-standalone
│   ├── bin/
│   │   └── python3.11              # Portable Python interpreter
│   └── lib/
│       └── python3.11/
│           └── site-packages/
│               ├── yaml/           # PyYAML (vendored)
│               └── boxctl/         # Core framework
│                   ├── __init__.py
│                   ├── cli.py
│                   ├── runner.py
│                   ├── discovery.py
│                   ├── logging.py
│                   ├── profiles.py
│                   ├── runbooks.py
│                   ├── doctor.py
│                   ├── scheduler.py
│                   └── output.py
├── scripts/                        # Bundled scripts
│   ├── baremetal/
│   │   ├── disk_health.py
│   │   ├── disk_io_latency_monitor.py
│   │   └── ... (~150 scripts)
│   └── k8s/
│       ├── pod_status.py
│       ├── node_health.py
│       └── ... (~60 scripts)
└── profiles/                       # Built-in profiles
    ├── k8s-worker.yaml
    └── database-server.yaml
```

### User Configuration

```
~/.config/boxctl/
├── config.yaml                     # Global settings
├── scripts/                        # User overrides (takes precedence)
│   └── baremetal/
│       └── disk_health.py          # Hotfix or custom version
├── profiles/                       # Custom profiles
│   └── my-server.yaml
└── runbooks/                       # Custom runbooks
    └── disk-triage.yaml

~/var/log/boxctl/                   # JSON logs from runs
├── 2025-02-01/
│   └── *.jsonl
└── latest -> 2025-02-01/
```

### Script Resolution Order

When running a script, boxctl checks:
1. `~/.config/boxctl/scripts/` - User overrides (hotfixes)
2. `/opt/boxctl/scripts/` - Bundled defaults

First match wins. This enables immediate hotfixes without any rebuild.

### The Wrapper Script

```bash
#!/bin/bash
# /opt/boxctl/bin/boxctl
set -euo pipefail

BOXCTL_HOME="${BOXCTL_HOME:-/opt/boxctl}"
BOXCTL_PYTHON="$BOXCTL_HOME/runtime/bin/python3.11"

exec "$BOXCTL_PYTHON" -m boxctl "$@"
```

Symlink to `/usr/local/bin/boxctl` for PATH access.

## Script Format

### Header Metadata

```python
#!/usr/bin/env python3
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart, storage, hardware]
#   requires: [smartctl]
#   privilege: root
#   related: [disk_space_forecaster, disk_life_predictor]
#   brief: Check disk health using SMART attributes

"""
Extended description if needed.
"""

from boxctl.core.output import Output
from boxctl.core.context import Context

def run(args: list, output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments passed to this script
        output: Structured output helper
        context: Execution context (for subprocess wrapping, testability)

    Returns:
        Exit code: 0=ok, 1=warning, 2=error
    """
    if not context.check_tool("smartctl"):
        output.error("smartctl not found")
        return 2

    result = context.run(["smartctl", "-H", "/dev/sda"])
    # ... process result ...

    output.emit({"disks": results})
    return 0 if all_healthy else 1


# Allow standalone execution for debugging
if __name__ == "__main__":
    import sys
    from boxctl.core.output import Output
    from boxctl.core.context import Context
    sys.exit(run(sys.argv[1:], Output(), Context()))
```

### Metadata Fields

| Field | Required | Description |
|-------|----------|-------------|
| `category` | Yes | `baremetal/<subsystem>` or `k8s/<resource>` |
| `tags` | Yes | List of searchable labels |
| `brief` | Yes | One-line description |
| `requires` | No | System tools needed (smartctl, mdadm, kubectl) |
| `privilege` | No | `root`, `sudo`, or omit for unprivileged |
| `related` | No | Other scripts that pair well |

### Context Object (Testability)

The `Context` object wraps subprocess calls, enabling:
- Real execution in production
- Mocked responses in tests
- Consistent error handling

```python
class Context:
    def run(self, cmd: list, **kwargs) -> subprocess.CompletedProcess:
        """Run a command, respecting test mode."""
        ...

    def check_tool(self, name: str) -> bool:
        """Check if a tool exists in PATH."""
        ...

    def read_file(self, path: str) -> str:
        """Read a file, mockable for tests."""
        ...
```

## Privilege Model

### Declaration

Scripts declare their privilege requirements:
```python
# boxctl:
#   privilege: root    # Requires root
#   privilege: sudo    # Can use sudo if available
#   # (omit for unprivileged)
```

### Execution Strategy

1. **Unprivileged scripts**: Run directly
2. **sudo scripts**: boxctl invokes `sudo` for that script only
3. **root scripts**:
   - If running as root: execute directly
   - If sudo available: use sudo
   - Otherwise: fail with clear message

```bash
$ boxctl run baremetal_disk_health
[sudo] password for gabe:
Running baremetal_disk_health (requires root via sudo)...
```

### Security Considerations

- boxctl itself never runs as root
- Privilege escalation is per-script, not global
- Audit log records which scripts ran with elevation
- `boxctl doctor` shows current privilege capabilities

## CLI Commands

### Discovery

```bash
boxctl list                          # All scripts with brief descriptions
boxctl list --category=baremetal/disk
boxctl list --tag=health
boxctl list --tag=health --tag=disk  # AND logic
boxctl search "memory leak"          # Fuzzy search briefs and tags

boxctl show baremetal_disk_health    # Full details + script-specific args
boxctl doctor                        # What can/can't run on this system
```

### Running Scripts

```bash
boxctl run baremetal_disk_health     # Single script
boxctl run --tag=disk                # All disk-related scripts
boxctl run --category=baremetal/disk # All in category
boxctl run --profile=database-server # All scripts in profile

# Flags
boxctl run --tag=disk --best-effort  # Skip scripts with missing deps
boxctl run --tag=disk --dry-run      # Show what would run
boxctl run --tag=disk --parallel=4   # Run 4 at a time
boxctl run --tag=disk -- --verbose   # Pass flags through to scripts
```

### Logs & History

```bash
boxctl logs                          # Today's runs
boxctl logs --date=2025-01-30
boxctl logs --script=baremetal_disk_health
boxctl logs --filter=error           # Only failures
boxctl logs --json                   # Raw JSON for piping
boxctl logs --tail                   # Follow mode
```

### Scheduling

```bash
boxctl schedule --profile=database-server --every=1h
boxctl schedule --tag=health --every=6h --mailto=ops@example.com
boxctl crontab                       # Show managed cron entries
```

### Profiles & Runbooks

```bash
boxctl run --profile=database-server
boxctl runbook disk-triage
boxctl runbook disk-triage --dry-run
boxctl runbook list
```

## Profiles

YAML bundles for server roles:

```yaml
# ~/.config/boxctl/profiles/database-server.yaml
name: database-server
description: PostgreSQL/MySQL database servers
scripts:
  - baremetal_disk_health
  - baremetal_disk_io_latency_monitor
  - baremetal_disk_space_forecaster
  - baremetal_memory_leak_detector
  - baremetal_load_average_monitor
  - baremetal_fd_exhaustion_monitor
  - baremetal_oom_killer_monitor
tags:
  - disk
  - memory
  - io
schedule: "0 */4 * * *"
```

## Runbooks

Conditional workflows with sequencing:

```yaml
# ~/.config/boxctl/runbooks/disk-triage.yaml
name: disk-triage
description: Investigate disk issues step by step
steps:
  - run: baremetal_disk_health
    on_failure: continue

  - run: baremetal_disk_io_latency_monitor

  - run: baremetal_disk_space_forecaster
    when: "{{ prev.exit_code == 0 }}"

  - run: baremetal_inode_exhaustion_monitor

  - group:
      parallel: true
      scripts:
        - baremetal_disk_queue_monitor
        - baremetal_disk_write_cache_audit
```

## Logging

### Log Format

JSONL in `~/var/log/boxctl/{date}/{script}.jsonl`:

```json
{
  "timestamp": "2025-02-01T14:32:05Z",
  "script": "baremetal_disk_health",
  "exit_code": 1,
  "duration_ms": 2340,
  "hostname": "db-prod-01",
  "invocation": "boxctl run --profile=database-server",
  "privilege": "sudo",
  "stdout_lines": 12,
  "stderr_lines": 2,
  "level": "warning",
  "summary": "2 disks healthy, 1 disk degraded"
}
```

### Log Levels

Derived from exit codes:
- `0` → `ok`
- `1` → `warning` (issues found)
- `2` → `error` (script failed to run)

### Syslog Integration

Optional in config:

```yaml
# ~/.config/boxctl/config.yaml
logging:
  syslog: true
  facility: local0
```

## Dependency Handling

### Preflight: `boxctl doctor`

```
$ boxctl doctor

System: db-prod-01 (Ubuntu 22.04)
User: gabe (uid=1000, groups: sudo,docker)

Runtime:
  ✓ boxctl        0.1.0
  ✓ python        3.11.7 (bundled)

Tools:
  ✓ smartctl      /usr/sbin/smartctl
  ✓ mdadm         /sbin/mdadm
  ✓ kubectl       /usr/local/bin/kubectl
  ✗ ceph          not found

Privileges:
  ✓ sudo          passwordless sudo available
  ✗ root          not running as root

Scripts available:
  baremetal/*     142/156 runnable (14 need missing tools)
  k8s/*            58/62 runnable  (4 need ceph)

User overrides:
  ~/.config/boxctl/scripts/baremetal/disk_health.py (overrides bundled)
```

### Runtime Behavior

**Default (fail fast):**
```bash
$ boxctl run baremetal_disk_health
Error: baremetal_disk_health requires smartctl (not found)
```

**Best effort:**
```bash
$ boxctl run --tag=disk --best-effort

Running 8 scripts (2 skipped - missing requirements)
...
Summary: 6 ok, 0 warnings, 0 errors, 2 skipped
```

## Configuration

### Global Config

```yaml
# ~/.config/boxctl/config.yaml

logging:
  dir: ~/var/log/boxctl
  retain_days: 30
  syslog: false

defaults:
  parallel: 1
  best_effort: false
  format: plain

# Additional script search paths
script_paths:
  - /opt/custom-scripts
```

### Environment Variables

```bash
BOXCTL_HOME=/opt/boxctl              # Installation root
BOXCTL_CONFIG=~/alt-config.yaml      # Config file override
BOXCTL_LOG_DIR=/tmp/boxctl-test      # Log directory override
BOXCTL_BEST_EFFORT=1                 # Enable best-effort mode
```

## Packaging & Distribution

### Build Process

Uses [python-build-standalone](https://github.com/indygreg/python-build-standalone) for portable Python:

```bash
# Download portable Python (~30MB)
PYTHON_VERSION="3.11.7"
curl -L "https://github.com/indygreg/python-build-standalone/releases/download/20240107/cpython-${PYTHON_VERSION}+20240107-x86_64-unknown-linux-gnu-install_only.tar.gz" \
  | tar xz -C build/runtime

# Install boxctl core + PyYAML into the bundled runtime
build/runtime/bin/pip install pyyaml
build/runtime/bin/pip install -e ./boxctl-core

# Copy scripts
cp -r scripts/ build/scripts/
cp -r profiles/ build/profiles/

# Create wrapper
cat > build/bin/boxctl << 'EOF'
#!/bin/bash
BOXCTL_HOME="${BOXCTL_HOME:-$(dirname $(dirname $(readlink -f "$0")))}"
exec "$BOXCTL_HOME/runtime/bin/python3.11" -m boxctl "$@"
EOF
chmod +x build/bin/boxctl

# Package
tar czf boxctl-0.1.0-linux-amd64.tar.gz -C build .
```

### Distribution

```bash
# Install
curl -fsSL https://github.com/yourorg/boxctl/releases/latest/download/boxctl-0.1.0-linux-amd64.tar.gz \
  | sudo tar xz -C /opt/boxctl

sudo ln -sf /opt/boxctl/bin/boxctl /usr/local/bin/boxctl

# Verify
boxctl version
boxctl doctor
```

### Updating Scripts Only

```bash
# Update just the scripts (no runtime rebuild needed)
curl -fsSL https://github.com/yourorg/boxctl/releases/latest/download/scripts.tar.gz \
  | sudo tar xz -C /opt/boxctl/scripts
```

### Version Info

```bash
$ boxctl version
boxctl 0.1.0 (linux-amd64)
Python: 3.11.7 (bundled)
Scripts: 156 baremetal, 62 k8s
User overrides: 1
Built: 2025-02-01T10:30:00Z
```

## Testing Strategy

### Requirements

- **Coverage target**: 80% minimum for all scripts
- **All scripts tested**: Every script must have tests before v1 release
- **Realistic mocks**: Use fixture files with real command outputs
- **K8s testing**: Minikube in CI is sufficient

### Test Structure

```
tests/
├── conftest.py                     # Shared fixtures, MockContext
├── fixtures/                       # Real command outputs
│   ├── smartctl/
│   │   ├── healthy_ssd.txt
│   │   ├── failing_hdd.txt
│   │   └── nvme_drive.txt
│   ├── kubectl/
│   │   ├── pods_running.json
│   │   ├── pods_pending.json
│   │   └── nodes_mixed.json
│   ├── proc/
│   │   ├── mdstat_healthy.txt
│   │   ├── mdstat_degraded.txt
│   │   └── meminfo_low.txt
│   └── ...
├── core/                           # Framework tests
│   ├── test_discovery.py
│   ├── test_runner.py
│   ├── test_profiles.py
│   └── test_runbooks.py
├── scripts/
│   ├── baremetal/
│   │   ├── test_disk_health.py
│   │   ├── test_disk_io_latency_monitor.py
│   │   └── ... (one per script)
│   └── k8s/
│       ├── test_pod_status.py
│       └── ... (one per script)
└── integration/                    # Minikube tests (CI only)
    └── k8s/
        └── test_real_k8s.py
```

### Fixture-Based Mocking

Fixtures contain real command outputs captured from actual systems:

```python
# tests/fixtures/smartctl/failing_hdd.txt
smartctl 7.2 2020-12-30 r5155
...
SMART overall-health self-assessment test result: FAILED!
...
Reallocated_Sector_Ct   0x0033   095   095   036    Pre-fail  Always       -       327
```

```python
# tests/conftest.py
import pytest
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"

@pytest.fixture
def mock_context():
    """Factory for creating MockContext with fixture data."""
    def _create(**overrides):
        return MockContext(**overrides)
    return _create

@pytest.fixture
def smartctl_fixtures():
    """Load all smartctl fixture files."""
    return {
        f.stem: f.read_text()
        for f in (FIXTURES / "smartctl").glob("*.txt")
    }

@pytest.fixture
def kubectl_fixtures():
    """Load all kubectl fixture files."""
    return {
        f.stem: json.loads(f.read_text())
        for f in (FIXTURES / "kubectl").glob("*.json")
    }
```

### MockContext Implementation

```python
# tests/conftest.py
class MockContext:
    """Mock Context for testing scripts without real system access."""

    def __init__(
        self,
        tools_available: list[str] = None,
        command_outputs: dict = None,
        file_contents: dict = None,
        env: dict = None,
    ):
        self.tools_available = set(tools_available or [])
        self.command_outputs = command_outputs or {}
        self.file_contents = file_contents or {}
        self.env = env or {}
        self.commands_run = []  # Track what was called

    def check_tool(self, name: str) -> bool:
        return name in self.tools_available

    def run(self, cmd: list, **kwargs) -> subprocess.CompletedProcess:
        self.commands_run.append(cmd)
        key = tuple(cmd)
        if key in self.command_outputs:
            output = self.command_outputs[key]
            if isinstance(output, Exception):
                raise output
            return subprocess.CompletedProcess(
                cmd, returncode=0, stdout=output, stderr=""
            )
        raise KeyError(f"No mock output for command: {cmd}")

    def read_file(self, path: str) -> str:
        if path in self.file_contents:
            return self.file_contents[path]
        raise FileNotFoundError(f"No mock content for: {path}")
```

### Example Script Test

```python
# tests/scripts/baremetal/test_disk_health.py
import pytest
from boxctl.scripts.baremetal import disk_health
from boxctl.core.output import Output

class TestDiskHealth:
    """Tests for baremetal_disk_health script."""

    def test_missing_smartctl(self, mock_context):
        """Script returns error when smartctl not available."""
        ctx = mock_context(tools_available=["lsblk"])
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 2
        assert "smartctl" in output.errors[0].lower()

    def test_all_disks_healthy(self, mock_context, smartctl_fixtures):
        """Script returns ok when all disks pass SMART."""
        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\nsdb disk",
                ("smartctl", "-H", "/dev/sda"): smartctl_fixtures["healthy_ssd"],
                ("smartctl", "-H", "/dev/sdb"): smartctl_fixtures["healthy_ssd"],
            }
        )
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 0
        assert len(output.data["disks"]) == 2
        assert all(d["status"] == "PASSED" for d in output.data["disks"])

    def test_one_disk_failing(self, mock_context, smartctl_fixtures):
        """Script returns warning when one disk fails SMART."""
        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk\nsdb disk",
                ("smartctl", "-H", "/dev/sda"): smartctl_fixtures["healthy_ssd"],
                ("smartctl", "-H", "/dev/sdb"): smartctl_fixtures["failing_hdd"],
            }
        )
        output = Output()

        exit_code = disk_health.run([], output, ctx)

        assert exit_code == 1  # warning
        assert output.data["disks"][1]["status"] == "FAILED"

    def test_json_output_format(self, mock_context, smartctl_fixtures):
        """Script produces valid structured output."""
        ctx = mock_context(
            tools_available=["smartctl", "lsblk"],
            command_outputs={
                ("lsblk", "-d", "-n", "-o", "NAME,TYPE"): "sda disk",
                ("smartctl", "-H", "/dev/sda"): smartctl_fixtures["healthy_ssd"],
            }
        )
        output = Output()

        disk_health.run(["--format=json"], output, ctx)

        assert "disks" in output.data
        assert "timestamp" in output.data
        assert "hostname" in output.data
```

### Collecting Real Fixtures

Script to capture real outputs for fixtures:

```bash
#!/bin/bash
# scripts/collect_fixtures.sh
# Run on real systems to capture fixture data

FIXTURE_DIR="tests/fixtures"

# smartctl
mkdir -p "$FIXTURE_DIR/smartctl"
for disk in /dev/sd?; do
    name=$(basename "$disk")
    sudo smartctl -H "$disk" > "$FIXTURE_DIR/smartctl/${name}_health.txt" 2>&1
    sudo smartctl -a "$disk" > "$FIXTURE_DIR/smartctl/${name}_full.txt" 2>&1
done

# kubectl (run in k8s cluster)
mkdir -p "$FIXTURE_DIR/kubectl"
kubectl get pods -A -o json > "$FIXTURE_DIR/kubectl/pods_all.json"
kubectl get nodes -o json > "$FIXTURE_DIR/kubectl/nodes.json"

# /proc files
mkdir -p "$FIXTURE_DIR/proc"
cat /proc/mdstat > "$FIXTURE_DIR/proc/mdstat.txt"
cat /proc/meminfo > "$FIXTURE_DIR/proc/meminfo.txt"
```

### K8s Integration Tests (Minikube)

```python
# tests/integration/k8s/test_real_k8s.py
import pytest
import subprocess

# Skip if minikube not available
pytestmark = pytest.mark.skipif(
    subprocess.run(["which", "minikube"], capture_output=True).returncode != 0,
    reason="minikube not available"
)

class TestK8sScriptsReal:
    """Integration tests against real minikube cluster."""

    @pytest.fixture(scope="class", autouse=True)
    def minikube_running(self):
        """Ensure minikube is running."""
        result = subprocess.run(
            ["minikube", "status", "--format={{.Host}}"],
            capture_output=True, text=True
        )
        if "Running" not in result.stdout:
            pytest.skip("minikube not running")

    def test_pod_status_real(self):
        """Run pod_status against real minikube."""
        from boxctl.scripts.k8s import pod_status
        from boxctl.core.output import Output
        from boxctl.core.context import Context  # Real context

        output = Output()
        exit_code = pod_status.run(
            ["--namespace=kube-system"],
            output,
            Context()  # Real execution
        )

        assert exit_code in (0, 1)  # ok or warning, not error
        assert "pods" in output.data
```

### CI Configuration

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up boxctl runtime
        run: ./scripts/setup-dev.sh
      - name: Run unit tests with coverage
        run: |
          pytest tests/ \
            --ignore=tests/integration \
            --cov=boxctl \
            --cov-report=xml \
            --cov-fail-under=80
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  k8s-integration:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Start minikube
        uses: medyagh/setup-minikube@master
      - name: Run k8s integration tests
        run: |
          pytest tests/integration/k8s/ -v

  lint-scripts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate all script metadata
        run: |
          ./boxctl lint --all --strict
```

### Coverage Enforcement

```toml
# pyproject.toml
[tool.coverage.run]
source = ["boxctl"]
branch = true

[tool.coverage.report]
fail_under = 80
exclude_lines = [
    "pragma: no cover",
    "if __name__ == .__main__.:",
    "raise NotImplementedError",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--strict-markers -v"
markers = [
    "integration: marks tests as integration tests (deselect with '-m not integration')",
]
```

## Migration Path

1. Create `boxctl-core/` project structure (framework only)
2. Build core framework (cli, runner, discovery, logging, context)
3. Set up build pipeline with python-build-standalone
4. Migrate scripts one category at a time:
   - Add header metadata
   - Refactor to `run(args, output, context)` signature
   - Add unit tests with mocked context
5. Add profiles and runbooks
6. CI/CD for releases

## Key Decisions Summary

| Decision | Choice |
|----------|--------|
| Scope | baremetal + k8s only (no AWS) |
| Architecture | Bundled runtime + external scripts |
| Python Runtime | python-build-standalone (~30MB) |
| CLI style | Verb-first (`boxctl run`, `boxctl list`) |
| Metadata | Header comments in each script |
| Orchestration | Profiles + Runbooks + Smart Groups |
| Scheduling | Cron generator (leverage existing infrastructure) |
| Alerting | Log levels + external shipper |
| Dependencies | Fail fast by default, `--best-effort` flag, `boxctl doctor` |
| Privilege Model | Per-script sudo, never run boxctl as root |
| Testability | Context injection for subprocess mocking |
| Target | Team of sysadmins |

## Appendix: Validation Findings

Design validated by multi-agent consensus (Claude, Gemini, Codex). Key issues addressed:

| Original Issue | Resolution |
|----------------|------------|
| Monolithic binary deployment friction | Bundled runtime + separate scripts |
| Scripts untestable without hardware | Context injection for mocking |
| Privilege model undefined | Per-script sudo with audit logging |
| Startup latency from module loading | Scripts loaded on-demand, not imported |
| Docstring metadata fragile | Build-time validation (`boxctl lint`) |
