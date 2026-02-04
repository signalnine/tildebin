# boxctl request - Script Request Feature

## Overview

Allow LLM agents to file GitHub/GitLab issues when they need a script capability that doesn't exist. This creates a feedback loop where investigation dead ends become feature requests.

## CLI Interface

```bash
boxctl request "Check Redis replication lag" \
  --searched "redis replication, redis lag, redis health" \
  --context "Debugging slow API responses, suspected Redis replica drift"
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `capability` | Yes | Description of the needed capability |
| `--searched` | No | Comma-separated search terms the agent tried |
| `--context` | No | Investigation context that led to this request |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Issue created successfully |
| 1 | Issue creation failed (API error, network) |
| 2 | Missing dependency (`gh`/`glab`) or config error |

## Platform Detection

Detection order (first match wins):

1. **Project config** - `.boxctl.yaml` in repo root
2. **User config** - `~/.config/boxctl/config.yaml`
3. **Auto-detect** - Parse `git remote get-url origin`:
   - Contains `github.com` → GitHub
   - Contains `gitlab.com` → GitLab
4. **Fail** - Clear error message listing options

### Config Format

```yaml
# .boxctl.yaml or ~/.config/boxctl/config.yaml
issue_platform: github  # or gitlab
```

## Issue Format

### GitHub (`gh issue create`)

```
Title: Script request: Check Redis replication lag
Labels: script-request

Body:
## Requested Capability
Check Redis replication lag

## Searches Tried
redis replication, redis lag, redis health

## Investigation Context
Debugging slow API responses, suspected Redis replica drift

---
*Filed by LLM agent via `boxctl request`*
```

### GitLab (`glab issue create`)

Same format, using `--label` instead of `--label` (same flag).

## Implementation

### New Files

**boxctl/cli/request.py**
```python
"""Request command for filing script requests."""

import subprocess
from pathlib import Path

from boxctl.core.config import get_issue_platform, detect_platform
from boxctl.core.context import Context


def add_request_parser(subparsers):
    """Add request subcommand."""
    parser = subparsers.add_parser(
        'request',
        help='Request a new script capability (files GitHub/GitLab issue)'
    )
    parser.add_argument('capability', help='Description of needed capability')
    parser.add_argument('--searched', help='Search terms tried (comma-separated)')
    parser.add_argument('--context', help='Investigation context')
    parser.set_defaults(func=run_request)


def run_request(args, context: Context = None):
    """Execute request command."""
    context = context or Context()

    # Determine platform
    platform = get_issue_platform()
    if not platform:
        platform = detect_platform(context)

    if not platform:
        print("Error: Could not determine issue platform.", file=sys.stderr)
        print("Set 'issue_platform' in .boxctl.yaml or ~/.config/boxctl/config.yaml", file=sys.stderr)
        print("Or ensure git remote points to github.com or gitlab.com", file=sys.stderr)
        return 2

    # Check for CLI tool
    cli_tool = 'gh' if platform == 'github' else 'glab'
    if not context.check_tool(cli_tool):
        print(f"Error: {cli_tool} CLI not found. Install it to file issues.", file=sys.stderr)
        return 2

    # Build issue body
    body = build_issue_body(args.capability, args.searched, args.context)
    title = f"Script request: {args.capability}"

    # Create issue
    if platform == 'github':
        cmd = ['gh', 'issue', 'create', '--title', title, '--body', body, '--label', 'script-request']
    else:
        cmd = ['glab', 'issue', 'create', '--title', title, '--description', body, '--label', 'script-request']

    try:
        result = context.run(cmd, check=True)
        return 0
    except subprocess.CalledProcessError as e:
        print(f"Error creating issue: {e.stderr}", file=sys.stderr)
        return 1


def build_issue_body(capability: str, searched: str | None, context: str | None) -> str:
    """Build the issue body markdown."""
    lines = [
        "## Requested Capability",
        capability,
        "",
    ]

    if searched:
        lines.extend([
            "## Searches Tried",
            searched,
            "",
        ])

    if context:
        lines.extend([
            "## Investigation Context",
            context,
            "",
        ])

    lines.extend([
        "---",
        "*Filed by LLM agent via `boxctl request`*",
    ])

    return "\n".join(lines)
```

**boxctl/core/config.py**
```python
"""Configuration loading with layered overrides."""

import os
from pathlib import Path
import yaml


def get_config_value(key: str) -> str | None:
    """Get config value with project -> user -> None precedence."""
    # Project config
    project_config = Path('.boxctl.yaml')
    if project_config.exists():
        with open(project_config) as f:
            data = yaml.safe_load(f) or {}
            if key in data:
                return data[key]

    # User config
    user_config = Path.home() / '.config' / 'boxctl' / 'config.yaml'
    if user_config.exists():
        with open(user_config) as f:
            data = yaml.safe_load(f) or {}
            if key in data:
                return data[key]

    return None


def get_issue_platform() -> str | None:
    """Get configured issue platform."""
    return get_config_value('issue_platform')


def detect_platform(context) -> str | None:
    """Auto-detect platform from git remote."""
    try:
        result = context.run(['git', 'remote', 'get-url', 'origin'], check=True)
        url = result.stdout.strip()

        if 'github.com' in url:
            return 'github'
        elif 'gitlab.com' in url:
            return 'gitlab'
    except Exception:
        pass

    return None
```

### Modified Files

**boxctl/cli/main.py** - Add import and subparser:
```python
from boxctl.cli.request import add_request_parser
# ...
add_request_parser(subparsers)
```

**skills/baremetal-troubleshooting/SKILL.md** - Add section:
```markdown
## Dead Ends

When you can't find a script for what you need:

1. Confirm no existing script covers it: `boxctl search "your terms"`
2. File a request:
   ```bash
   boxctl request "capability needed" \
     --searched "terms you tried" \
     --context "what you were investigating"
   ```
3. Document the gap in your investigation summary
4. Continue with alternative approaches if possible
```

**skills/k8s-troubleshooting/SKILL.md** - Same section added.

### Test Files

**tests/cli/test_request.py**
- Test missing `gh`/`glab` returns exit 2
- Test successful issue creation (mock subprocess)
- Test body formatting with all fields
- Test body formatting with optional fields omitted
- Test platform detection from git remote
- Test config override precedence

**tests/core/test_config.py**
- Test project config takes precedence
- Test user config used as fallback
- Test returns None when no config
- Test auto-detect github.com
- Test auto-detect gitlab.com
- Test auto-detect fails gracefully

## Skill Integration

The troubleshooting skills guide agents to file requests at dead ends:

**Trigger conditions:**
- Agent searches for scripts but finds nothing relevant
- Agent runs scripts but needs data none provide
- Investigation hits a wall due to missing capability

**Not a separate skill** - guidance added to existing troubleshooting skills to keep discovery simple.

## Dependencies

| Platform | CLI Tool | Install |
|----------|----------|---------|
| GitHub | `gh` | `brew install gh` / `apt install gh` |
| GitLab | `glab` | `brew install glab` / `apt install glab` |

Scripts check for tool availability and exit with code 2 if missing.
