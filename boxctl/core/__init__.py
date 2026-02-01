"""Core boxctl functionality."""

from boxctl.core.context import Context
from boxctl.core.discovery import Script, discover_scripts, filter_scripts
from boxctl.core.metadata import MetadataError, parse_metadata, validate_metadata
from boxctl.core.output import Output
from boxctl.core.runner import ScriptResult, needs_privilege, run_script

__all__ = [
    "Context",
    "MetadataError",
    "Output",
    "Script",
    "ScriptResult",
    "discover_scripts",
    "filter_scripts",
    "needs_privilege",
    "parse_metadata",
    "run_script",
    "validate_metadata",
]
