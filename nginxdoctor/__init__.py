"""Find the nginx traps that only show up in production."""

__version__ = "0.1.0"

from .core import (
    SEVERITIES,
    ConfigError,
    Directive,
    Finding,
    lint,
    parse,
    parse_file,
    severity_at_least,
    walk,
)

__all__ = [
    "SEVERITIES",
    "ConfigError",
    "Directive",
    "Finding",
    "lint",
    "parse",
    "parse_file",
    "severity_at_least",
    "walk",
]
