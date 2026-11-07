"""Parse an nginx configuration and explain what will go wrong at runtime.

The parser is deliberately small: nginx configuration is a tree of
``directive arg arg;`` statements with optional ``{ ... }`` blocks, and that is
all this module models. Everything interesting is in the rules, which encode
the traps that are hard to see by reading a config file:

* ``proxy_pass`` rewriting the request URI depending on whether the location
  prefix and the proxy URI end in a slash;
* ``add_header`` replacing, not merging, the inherited set once any
  ``add_header`` appears in a nested block;
* ``if`` behaving as a separate configuration context;
* ``alias`` mapping the remainder of the URI onto a filesystem path.

>>> config = "server { listen 80; server_name a; location /api/ { proxy_pass http://app; } }"
>>> [f.code for f in lint(parse(config))]
['proxy-host-header']

>>> len(parse("server { listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; }"))
1
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "ConfigError",
    "Directive",
    "Finding",
    "SEVERITIES",
    "lint",
    "parse",
    "parse_file",
    "severity_at_least",
    "walk",
]

SEVERITIES = ("info", "low", "medium", "high", "error")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}


class ConfigError(ValueError):
    """Raised when the configuration cannot be tokenised or parsed."""


@dataclass
class Directive:
    """One directive, optionally with a block of child directives."""

    name: str
    args: List[str] = field(default_factory=list)
    block: Optional[List["Directive"]] = None
    file: str = "nginx.conf"
    line: int = 0

    @property
    def has_block(self) -> bool:
        return self.block is not None

    def arg(self, index: int, default: str = "") -> str:
        return self.args[index] if index < len(self.args) else default

    def children(self, name: str) -> List["Directive"]:
        return [d for d in (self.block or []) if d.name == name]

    def child(self, name: str) -> Optional["Directive"]:
        for d in self.block or []:
            if d.name == name:
                return d
        return None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "Directive(%r, %r, block=%s, line=%d)" % (
            self.name,
            self.args,
            "yes" if self.has_block else "no",
            self.line,
        )


@dataclass
class Finding:
    code: str
    severity: str
    message: str
    hint: str
    file: str
    line: int

    def as_dict(self) -> dict:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "hint": self.hint,
            "file": self.file,
            "line": self.line,
        }

    def __str__(self) -> str:
        return "%s:%d  %-7s %-26s %s" % (
            self.file,
            self.line,
            self.severity,
            self.code,
            self.message,
        )


def severity_at_least(severity: str, threshold: str) -> bool:
    """Return True when *severity* is at or above *threshold*.

    >>> severity_at_least("high", "medium")
    True
    >>> severity_at_least("low", "high")
    False
    """
    return _SEVERITY_RANK[severity] >= _SEVERITY_RANK[threshold]


# --------------------------------------------------------------------------
# Tokeniser
# --------------------------------------------------------------------------


def _tokenize(text: str, filename: str) -> Iterable[Tuple[str, str, int]]:
    index, length, line = 0, len(text), 1
    while index < length:
        char = text[index]
        if char in " \t\r":
            index += 1
        elif char == "\n":
            line += 1
            index += 1
        elif char == "#":
            while index < length and text[index] != "\n":
                index += 1
        elif char in "\"'":
            quote = char
            start = line
            index += 1
            pieces: List[str] = []
            while index < length and text[index] != quote:
                if text[index] == "\\" and index + 1 < length:
                    pieces.append(text[index + 1])
                    index += 2
                    continue
                if text[index] == "\n":
                    line += 1
                pieces.append(text[index])
                index += 1
            if index >= length:
                raise ConfigError(
                    "%s:%d: unterminated %s quote" % (filename, start, quote)
                )
            index += 1
            yield ("WORD", "".join(pieces), start)
        elif char in "{};":
            yield (char, char, line)
            index += 1
        else:
            start = line
            pieces = []
            while index < length and text[index] not in " \t\r\n;{}#\"'":
                pieces.append(text[index])
                index += 1
            yield ("WORD", "".join(pieces), start)


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------


def parse(text: str, filename: str = "nginx.conf") -> List[Directive]:
    """Parse *text* into a list of top-level directives."""
    tokens = list(_tokenize(text, filename))
    position = 0

    def parse_block(is_top: bool) -> List[Directive]:
        nonlocal position
        out: List[Directive] = []
        while position < len(tokens):
            kind, value, line = tokens[position]
            if kind == "}":
                if is_top:
                    raise ConfigError("%s:%d: unexpected '}'" % (filename, line))
                position += 1
                return out
            if kind == ";":
                raise ConfigError("%s:%d: unexpected ';'" % (filename, line))
            if kind != "WORD":
                raise ConfigError("%s:%d: unexpected '{'" % (filename, line))
            name = value
            position += 1
            args: List[str] = []
            while position < len(tokens) and tokens[position][0] == "WORD":
                args.append(tokens[position][1])
                position += 1
            if position >= len(tokens):
                raise ConfigError(
                    "%s:%d: directive %r is not terminated" % (filename, line, name)
                )
            kind, _, _ = tokens[position]
            if kind == ";":
                position += 1
                out.append(Directive(name, args, None, filename, line))
            elif kind == "{":
                position += 1
                children = parse_block(False)
                out.append(Directive(name, args, children, filename, line))
            else:
                raise ConfigError(
                    "%s:%d: expected ';' or '{' after %r" % (filename, line, name)
                )
        if not is_top:
            raise ConfigError("%s: unexpected end of file, missing '}'" % filename)
        return out

    return parse_block(True)


def parse_file(path: str) -> List[Directive]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return parse(handle.read(), path)


def walk(
    directives: Sequence[Directive], ancestors: Tuple[Directive, ...] = ()
) -> Iterable[Tuple[Directive, Tuple[Directive, ...]]]:
    """Yield ``(directive, ancestors)`` for every directive in the tree."""
    for directive in directives:
        yield directive, ancestors
        if directive.block:
            yield from walk(directive.block, ancestors + (directive,))


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


def _http_blocks(tree: Sequence[Directive]) -> List[Directive]:
    blocks = [d for d in tree if d.name == "http"]
    return blocks or tree


def _servers(tree: Sequence[Directive]) -> List[Directive]:
    servers: List[Directive] = []
    for block in _http_blocks(tree):
        servers.extend(block.children("server"))
    # A config may be a bare server block, or a single file included into one.
    servers.extend(d for d in tree if d.name == "server")
    return servers


def _proxy_uri(target: str) -> str:
    """Return the path part of a proxy target, or '' when there is none."""
    if "://" not in target:
        return ""
    rest = target.split("://", 1)[1]
    slash = rest.find("/")
    return rest[slash:] if slash >= 0 else ""


def _has_head(directives: Sequence[Directive], name: str) -> bool:
    for directive in directives:
        if directive.name == name:
            return True
        if directive.block and _has_head(directive.block, name):
            return True
    return False


def _inherited(directives: Sequence[Directive], name: str) -> bool:
    return any(d.name == name for d in directives)


def _is_ssl_server(server: Directive) -> bool:
    for listen in server.children("listen"):
        if any("ssl" == arg for arg in listen.args):
            return True
    return False


def lint(tree: Sequence[Directive], filename: str = "") -> List[Finding]:
    """Return every finding for a parsed configuration."""
    findings: List[Finding] = []

    def add(code, severity, message, hint, directive):
        findings.append(
            Finding(
                code=code,
                severity=severity,
                message=message,
                hint=hint,
                file=directive.file if directive.line else (filename or directive.file),
                line=directive.line,
            )
        )

    servers = _servers(tree)
    seen_names: dict = {}

    for server in servers:
        server_names = server.children("server_name")
        listens = server.children("listen")
        if not listens:
            add(
                "server-without-listen",
                "high",
                "server block has no listen directive",
                "A server block without listen is never reached; nginx inherits "
                "listen 80 but a missing directive almost always means a copy "
                "error.",
                server,
            )
        if not server_names:
            add(
                "server-without-name",
                "high",
                "server block has no server_name",
                "Without server_name the block only answers as the default "
                "server. If it is not marked default_server this block is "
                "probably dead.",
                server,
            )
        for name_directive in server_names:
            for name in name_directive.args:
                key = (name, tuple(sorted(a for a in _listen_keys(listens))))
                if name not in ("", "_", "localhost") and key in seen_names:
                    add(
                        "duplicate-server-name",
                        "high",
                        "server_name %r is declared more than once on the same listen"
                        % name,
                        "nginx answers with the first matching block, so the "
                        "second one silently never serves this host. Remove one, "
                        "or split them by port.",
                        name_directive,
                    )
                seen_names[key] = name_directive

        if _is_ssl_server(server):
            protocols = server.child("ssl_protocols")
            inherited_protocols = _ancestors_of(tree, server, "ssl_protocols")
            if protocols:
                for arg in protocols.args:
                    if arg in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        add(
                            "weak-tls-version",
                            "high",
                            "ssl_protocols enables %s" % arg,
                            "These versions are deprecated and fail modern "
                            "compliance scans. Use 'TLSv1.2 TLSv1.3'.",
                            protocols,
                        )
            elif not inherited_protocols:
                add(
                    "tls-defaults",
                    "medium",
                    "TLS server relies on the default ssl_protocols",
                    "Older nginx builds default to versions that include "
                    "TLSv1/1.1. State 'ssl_protocols TLSv1.2 TLSv1.3' "
                    "explicitly.",
                    server,
                )
            if not server.child("ssl_certificate") and not _ancestors_of(
                tree, server, "ssl_certificate"
            ):
                add(
                    "ssl-without-certificate",
                    "error",
                    "listen ... ssl but no ssl_certificate is defined",
                    "nginx refuses to start with a handshake error. Add "
                    "ssl_certificate and ssl_certificate_key, or remove the "
                    "ssl flag from listen.",
                    server,
                )
            cert = server.child("ssl_certificate")
            if cert and not server.child("ssl_certificate_key"):
                add(
                    "certificate-without-key",
                    "error",
                    "ssl_certificate without ssl_certificate_key",
                    "The certificate cannot be used without its private key.",
                    cert,
                )

        # add_header does not merge: a nested add_header discards inherited ones.
        server_headers = server.children("add_header")
        server_header_names = {
            header.arg(0) for header in server_headers if header.args
        }
        if server_headers:
            for location in server.children("location"):
                local_headers = location.children("add_header")
                if not local_headers:
                    continue
                local_names = {header.arg(0) for header in local_headers if header.args}
                missing = server_header_names - local_names
                if missing:
                    add(
                        "add-header-shadowing",
                        "high",
                        "location add_header drops server-level header(s): %s"
                        % ", ".join(sorted(missing)),
                        "nginx replaces the inherited array as soon as a nested "
                        "add_header exists. Repeat the server-level headers inside "
                        "the location, or move them into a snippet included by both.",
                        location,
                    )

        for location in server.children("location"):
            findings.extend(_lint_location(location, server, add, tree))

    # Whole-tree checks that do not need a server context.
    for directive, _ancestors in walk(tree):
        if directive.name == "if":
            if not _if_is_safe(directive):
                add(
                    "if-non-rewrite",
                    "medium",
                    "if block contains directives nginx does not support there",
                    "'if' is evaluated in a separate configuration context. Only "
                    "return, rewrite and set are safe. Use 'map' for conditional "
                    "values and a named location for conditional proxying.",
                    directive,
                )

    findings.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.file, f.line))
    return findings


def _listen_keys(listens: Sequence[Directive]) -> List[str]:
    keys: List[str] = []
    for listen in listens:
        keys.append(listen.arg(0, "80"))
    return keys or ["80"]


def _ancestors_of(
    tree: Sequence[Directive], target: Directive, name: str
) -> bool:
    """True when *name* is set on an ancestor of *target*."""
    for directive, ancestors in walk(tree):
        if directive is target:
            return any(ancestor.child(name) for ancestor in ancestors)
    return False


def _if_is_safe(directive: Directive) -> bool:
    allowed = {"return", "rewrite", "set", "break"}
    for child in directive.block or []:
        if child.name not in allowed:
            return False
    return True


def _lint_location(location: Directive, server: Directive, add, tree) -> List[Finding]:
    out: List[Finding] = []
    prefix = location.arg(0)
    modifiers = [a for a in location.args if a in ("=", "~", "~*", "^~")]
    is_regex = any(m in ("~", "~*") for m in modifiers)
    proxies = location.children("proxy_pass")
    handlers = {"proxy_pass", "root", "alias", "return", "try_files", "fastcgi_pass",
                "uwsgi_pass", "grpc_pass", "empty_gif", "index"}

    def emit(code, severity, message, hint, directive=None):
        target = directive or location
        out.append(
            Finding(
                code=code,
                severity=severity,
                message=message,
                hint=hint,
                file=target.file,
                line=target.line,
            )
        )

    if not any(location.child(h) for h in handlers):
        emit(
            "location-without-handler",
            "medium",
            "location %r has no handler (proxy_pass, root, alias, return, try_files)"
            % prefix,
            "A location with no handler falls through to the enclosing context, "
            "which is rarely what the author intended.",
        )

    if location.child("root") and location.child("alias"):
        emit(
            "root-and-alias",
            "error",
            "location %r sets both root and alias" % prefix,
            "Only one of root and alias may be effective. nginx uses alias and "
            "the root directive is dead code that will confuse the next editor.",
        )

    alias = location.child("alias")
    if alias and not is_regex and not prefix.endswith("/") and prefix not in ("/",):
        emit(
            "alias-without-trailing-slash",
            "high",
            "location %r with alias but no trailing slash" % prefix,
            "alias replaces the matched prefix with the path, so '/static/' + "
            "/app.css becomes '<alias>app.css' rather than '<alias>/app.css'. "
            "Add the trailing slash to both sides.",
            alias,
        )

    for if_block in location.children("if"):
        for grandchild in if_block.block or []:
            if grandchild.name == "proxy_pass":
                emit(
                    "proxy-pass-inside-if",
                    "high",
                    "proxy_pass inside an if block",
                    "Only return and rewrite are reliable in if. Use a "
                    "named location and 'error_page 418 = @fallback', or "
                    "a 'map' to choose the upstream.",
                    grandchild,
                )

    for proxy in proxies:
        target = proxy.arg(0)
        uri = _proxy_uri(target)

        if "$" in target and not (_has_head(location.block or [], "resolver")
                                   or _has_head(server.block or [], "resolver")):
            emit(
                "proxy-pass-variable-without-resolver",
                "error",
                "proxy_pass uses a variable but no resolver is configured",
                "A variable in proxy_pass is resolved at request time. Without a "
                "resolver nginx fails with 'no resolver defined to resolve'. Add "
                "'resolver 127.0.0.53 valid=30s;' and use a variable for the "
                "upstream host.",
                proxy,
            )

        if uri and not is_regex:
            location_slash = prefix.endswith("/")
            uri_slash = uri.endswith("/")
            if uri_slash != location_slash:
                emit(
                    "proxy-uri-slash-mismatch",
                    "high",
                    "location %r and proxy_pass %r disagree about the trailing slash"
                    % (prefix, target),
                    "When proxy_pass has a URI, nginx replaces the matched "
                    "location prefix with it. A trailing slash on one side and "
                    "not the other silently duplicates or drops a path segment — "
                    "the most common cause of a 404 that works in curl.",
                    proxy,
                )

        if not _has_head(location.block or [], "proxy_set_header"):
            emit(
                "proxy-host-header",
                "medium",
                "proxy_pass without proxy_set_header Host",
                "By default nginx forwards the client's Host header. Most "
                "frameworks build absolute URLs from it, so a proxy in front of "
                "an app should set 'Host $host' (and X-Forwarded-For / "
                "X-Forwarded-Proto) explicitly.",
                proxy,
            )

        if _is_ssl_server(server) and not any(
            "X-Forwarded-Proto" in " ".join(d.args)
            for d in location.children("proxy_set_header")
        ):
            emit(
                "missing-forwarded-proto",
                "medium",
                "TLS server proxies without X-Forwarded-Proto",
                "The backend cannot tell HTTPS from HTTP, so it will generate "
                "http:// redirects and cookies without the secure flag. Set "
                "'proxy_set_header X-Forwarded-Proto $scheme'.",
                proxy,
            )

        if "$request_uri" in " ".join(proxy.args) and uri:
            emit(
                "proxy-pass-uri-with-request-uri",
                "high",
                "proxy_pass combines a URI part with $request_uri",
                "When a URI is present nginx uses the rewritten path; appending "
                "$request_uri duplicates the location prefix. Use proxy_pass "
                "without a URI to forward the original request unchanged.",
                proxy,
            )

    try_files = location.child("try_files")
    if try_files and len(try_files.args) >= 2:
        last = try_files.args[-1]
        if not last.startswith(("@", "=", "/", "http://", "https://")):
            emit(
                "try-files-relative-fallback",
                "medium",
                "try_files falls back to a relative path %r" % last,
                "Relative fallbacks resolve inside the location prefix and can "
                "loop. Use a leading path ('/index.html'), a named location "
                "('@app') or '=404'.",
                try_files,
            )
        elif (
            last.startswith("/")
            and prefix not in ("/", "")
            and prefix.endswith("/")
            and last.startswith(prefix)
        ):
            emit(
                "try-files-loop",
                "high",
                "try_files falls back to %r inside its own location prefix" % last,
                "The fallback re-enters the same location, which re-runs "
                "try_files. Use '=404' or a named location.",
                try_files,
            )

    return out
