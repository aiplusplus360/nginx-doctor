"""Command line interface for nginx-doctor."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Sequence

from .core import (
    SEVERITIES,
    ConfigError,
    Finding,
    lint,
    parse,
    parse_file,
    severity_at_least,
)

__version__ = "0.1.0"

_RULE_NOTES = {
    "proxy-uri-slash-mismatch": (
        "location /api { proxy_pass http://app/; }  ->  /api/users becomes /users\n"
        "location /api/ { proxy_pass http://app; }  ->  /api/users becomes /api/users\n"
        "location /api/ { proxy_pass http://app/; } ->  /api/users becomes /users\n"
        "Pick one convention and keep the slashes symmetric."
    ),
    "add-header-shadowing": (
        "add_header is an array directive. Its value is inherited only when the "
        "child block declares none. One add_header in a location removes every "
        "header set at server level in that location."
    ),
    "if-non-rewrite": (
        "if creates a nested configuration context with its own directive set. "
        "Only return, rewrite, set and break behave predictably."
    ),
    "alias-without-trailing-slash": (
        "alias performs a prefix replacement, not a concatenation. Both the "
        "location prefix and the alias path must end in a slash."
    ),
}


def _iter_configs(paths: Sequence[str]) -> List[str]:
    files: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            for base, _dirs, names in os.walk(path):
                for name in sorted(names):
                    if name.endswith((".conf", ".nginx")):
                        files.append(os.path.join(base, name))
        else:
            files.append(path)
    return files


def _collect(paths: Sequence[str]) -> List[Finding]:
    findings: List[Finding] = []
    for path in _iter_configs(paths):
        tree = parse_file(path)
        findings.extend(lint(tree, filename=path))
    return findings


def _format_table(findings: Sequence[Finding]) -> str:
    if not findings:
        return "no findings"
    lines = ["%-42s %-7s %s" % ("LOCATION", "SEV", "FINDING")]
    lines.append("-" * 96)
    for finding in findings:
        location = "%s:%d" % (os.path.basename(finding.file), finding.line)
        lines.append("%-42s %-7s %s" % (location, finding.severity, finding.message))
        for wrapped in _wrap(finding.hint, 88):
            lines.append(" " * 50 + wrapped)
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = ", ".join(
        "%d %s" % (counts[severity], severity)
        for severity in reversed(SEVERITIES)
        if severity in counts
    )
    lines.append("-" * 96)
    lines.append("%d finding(s): %s" % (len(findings), summary))
    return "\n".join(lines)


def _wrap(text: str, width: int) -> List[str]:
    words = text.split()
    lines, current = [], ""
    for word in words:
        if len(current) + len(word) + 1 > width and current:
            lines.append(current)
            current = word
        else:
            current = (current + " " + word).strip()
    if current:
        lines.append(current)
    return lines


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nginx-doctor",
        description="Lint an nginx configuration and explain each finding.",
    )
    parser.add_argument("paths", nargs="*", default=["."],
                        help="config files or directories (default: .)")
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument("--fail-on", choices=SEVERITIES, default="high",
                        help="exit 1 when a finding at or above this severity exists")
    parser.add_argument("--explain", metavar="CODE", help="explain one rule and exit")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.explain:
        note = _RULE_NOTES.get(args.explain)
        if note is None:
            sys.stderr.write("unknown rule: %s\n" % args.explain)
            return 2
        print(note)
        return 0

    try:
        findings = _collect(args.paths or ["."])
    except (ConfigError, OSError) as exc:
        sys.stderr.write("nginx-doctor: %s\n" % exc)
        return 2

    if args.format == "json":
        print(json.dumps(
            {"findings": [f.as_dict() for f in findings], "count": len(findings)},
            indent=2,
        ))
    else:
        print(_format_table(findings))

    failing = [f for f in findings if severity_at_least(f.severity, args.fail_on)]
    return 1 if failing else 0
