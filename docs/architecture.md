# Architecture

System design overview for boxctl.

## Module Structure

```
boxctl/
├── cli.py              # CLI entry point
├── __init__.py         # Package version
├── __main__.py         # python -m boxctl support
├── core/               # Core framework
│   ├── __init__.py     # Public API exports
│   ├── context.py      # Execution context for testability
│   ├── output.py       # Structured output collection
│   ├── metadata.py     # YAML metadata parsing
│   ├── discovery.py    # Script discovery and filtering
│   ├── runner.py       # Script execution
│   ├── linter.py       # Metadata validation
│   ├── profiles.py     # Execution profiles
│   └── logging.py      # Logging utilities
└── lib/                # Shared utilities
    ├── __init__.py
    ├── process.py      # Process utilities
    └── filesystem.py   # Filesystem utilities

scripts/
├── baremetal/          # Baremetal monitoring scripts
│   ├── disk/
│   ├── memory/
│   ├── network/
│   └── ...
└── k8s/                # Kubernetes scripts
    ├── pods/
    ├── nodes/
    └── ...

tests/
├── conftest.py         # Pytest fixtures (MockContext)
├── fixtures/           # Test data files
└── scripts/            # Script tests
```

## Data Flow

```
                      ┌─────────────┐
                      │    CLI      │
                      │   cli.py    │
                      └──────┬──────┘
                             │
                 ┌───────────┼───────────┐
                 ▼           ▼           ▼
         ┌───────────┐ ┌──────────┐ ┌────────┐
         │  discover │ │   run    │ │ search │
         │  scripts  │ │  script  │ │        │
         └─────┬─────┘ └────┬─────┘ └───┬────┘
               │            │           │
               ▼            ▼           ▼
        ┌────────────┐ ┌─────────┐ ┌────────────┐
        │  Script    │ │ Runner  │ │  Filter    │
        │ Discovery  │ │         │ │            │
        └─────┬──────┘ └────┬────┘ └────────────┘
              │             │
              ▼             ▼
       ┌────────────┐ ┌─────────────┐
       │  Metadata  │ │   Script    │
       │  Parser    │ │   Output    │
       └────────────┘ └─────────────┘
```

## Core Components

### Context (`boxctl/core/context.py`)

Wraps all external dependencies to enable testing.

```python
class Context:
    def check_tool(name: str) -> bool         # Check if tool in PATH
    def run(cmd, **kwargs) -> CompletedProcess # Run subprocess
    def read_file(path: str) -> str           # Read file contents
    def file_exists(path: str) -> bool        # Check file exists
    def glob(pattern, root) -> list[str]      # Find files
    def get_env(key, default) -> str          # Environment variable
    def cpu_count() -> int                    # CPU count
```

**Design principle:** Scripts never import `subprocess`, `os`, or `pathlib` directly. All external operations go through Context, making scripts fully testable with MockContext.

### Output (`boxctl/core/output.py`)

Collects structured output from scripts.

```python
class Output:
    data: dict           # Structured data
    errors: list[str]    # Error messages
    warnings: list[str]  # Warning messages

    def emit(data: dict) -> None     # Store structured data
    def error(message: str) -> None  # Record error
    def warning(message: str) -> None # Record warning
    def set_summary(summary: str) -> None
    def to_json() -> str             # JSON serialization
    def to_plain() -> str            # Plain text
```

**Design principle:** Scripts build up data via `emit()` rather than printing directly. This enables consistent output formatting and testing.

### Metadata (`boxctl/core/metadata.py`)

Parses YAML metadata from script headers.

```python
def parse_metadata(content: str) -> dict | None
def validate_metadata(metadata: dict) -> list[str]  # Returns warnings

# Required fields
REQUIRED_FIELDS = {"category", "tags", "brief"}
```

**Metadata format:**
```python
# boxctl:
#   category: baremetal/disk
#   tags: [health, smart]
#   brief: Check disk health
#   requires: [smartctl]
#   privilege: root
#   related: [disk_space]
```

### Discovery (`boxctl/core/discovery.py`)

Finds and loads scripts with valid metadata.

```python
@dataclass
class Script:
    name: str           # Filename
    path: Path          # Full path
    category: str       # e.g., "baremetal/disk"
    tags: list[str]     # Search tags
    brief: str          # One-line description
    requires: list[str] # Required tools
    privilege: str      # "root" or "user"
    related: list[str]  # Related scripts

def discover_scripts(directory: Path) -> list[Script]
def filter_scripts(scripts, category, tags) -> list[Script]
```

**Discovery process:**
1. Recursively find all `.py` files
2. Parse metadata header from each file
3. Skip files without valid `# boxctl:` header
4. Return list of Script dataclass instances

### Runner (`boxctl/core/runner.py`)

Executes scripts and captures output.

```python
@dataclass
class ScriptResult:
    script_name: str
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    success: bool  # Property: returncode == 0 and not timed_out

def run_script(
    script_path: Path,
    args: list[str] = None,
    timeout: int = 60,
    use_sudo: bool = False,
) -> ScriptResult

def needs_privilege(script_path: Path) -> bool
```

## Script Contract

Every script must implement this interface:

```python
def run(args: list[str], output: Output, context: Context) -> int:
    """
    Main entry point.

    Args:
        args: Command-line arguments (sys.argv[1:] equivalent)
        output: Output helper for structured data
        context: Execution context (real or mock)

    Returns:
        Exit code: 0=success, 1=issues, 2=error
    """
```

**Contract guarantees:**
- Scripts receive all external dependencies via parameters
- No global state or direct system calls
- Consistent exit code semantics
- Structured output via Output class

## Testability

The architecture is designed for comprehensive testing without external dependencies.

### MockContext

Test fixture that simulates external system:

```python
class MockContext:
    def __init__(
        self,
        tools_available: list[str] = None,
        command_outputs: dict[tuple, str] = None,
        file_contents: dict[str, str] = None,
        env: dict[str, str] = None,
    ):
        ...

    def check_tool(name) -> bool  # Returns name in tools_available
    def run(cmd) -> CompletedProcess  # Returns from command_outputs
    def read_file(path) -> str  # Returns from file_contents
```

### Test Example

```python
def test_disk_health_detects_failing_drive(mock_context, fixtures_dir):
    from scripts.baremetal import disk_health

    ctx = mock_context(
        tools_available=['smartctl'],
        command_outputs={
            ('smartctl', '-a', '/dev/sda'): (
                fixtures_dir / 'disk' / 'smart_failing.txt'
            ).read_text(),
        }
    )
    output = Output()

    exit_code = disk_health.run(['--device', '/dev/sda'], output, ctx)

    assert exit_code == 1
    assert 'failing' in output.data['status'].lower()
```

## Extension Points

### Adding New Categories

1. Create directory under `scripts/` (e.g., `scripts/baremetal/newcat/`)
2. Scripts in that directory use category `baremetal/newcat`
3. No code changes needed - discovery is automatic

### Adding New Output Formats

Modify `cli.py` to add format handling:

```python
parser.add_argument('--format', choices=['plain', 'json', 'csv', 'table'])
```

### Adding New Metadata Fields

1. Add field to `REQUIRED_FIELDS` or as optional in `metadata.py`
2. Add to `Script` dataclass in `discovery.py`
3. Update documentation

## Design Decisions

### Why dependency injection?

Scripts that directly call `subprocess.run()` or read files are hard to test. By passing Context, tests can inject MockContext with known outputs.

### Why YAML metadata?

- Human-readable and writable
- Standard format with good tooling
- Supports complex data (lists, nesting)
- Easy to parse in Python

### Why exit codes 0/1/2?

Following Unix conventions:
- 0: Success (useful in shell scripts: `if boxctl run disk_health; then`)
- 1: "Soft" failure (script ran but found issues)
- 2: "Hard" failure (script couldn't run)

### Why structured Output?

- Enables JSON output without script changes
- Separates data from presentation
- Makes testing assertions cleaner
- Supports future output formats (CSV, table, etc.)

## See Also

- [CLI Reference](cli-reference.md) - Command documentation
- [Writing Scripts](writing-scripts.md) - Script development guide
