# nginx-doctor

**Lint an nginx config and explain what will go wrong at runtime — the four `proxy_pass` traps, header inheritance, `if` semantics, and the TLS defaults nobody sets.**

[![CI](https://github.com/aiplusplus360/nginx-doctor/actions/workflows/ci.yml/badge.svg)](https://github.com/aiplusplus360/nginx-doctor/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)](pyproject.toml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```console
$ nginx-doctor /etc/nginx
nginx.conf:23  high    duplicate-server-name       server_name 'example.com' is declared more than once on the same listen
nginx.conf:31  high    proxy-uri-slash-mismatch    location '/api' and proxy_pass 'http://app/' disagree about the trailing slash
nginx.conf:38  high    add-header-shadowing        location add_header drops server-level header(s): X-Frame-Options
nginx.conf:52  error   ssl-without-certificate     listen ... ssl but no ssl_certificate is defined
nginx.conf:57  high    weak-tls-version            ssl_protocols enables TLSv1

5 finding(s): 1 error, 4 high
```

---

## Why this exists

`nginx -t` answers one question: *is this syntactically valid?* Every config below passes `nginx -t` and is broken.

**The trailing slash.** `location /api { proxy_pass http://app/; }` rewrites `/api/users` to `/users`. Swap either slash and the behaviour changes again. There are four combinations and two of them are wrong for any given backend. Nothing warns you; you get a 404 that works when you `curl` the upstream directly.

**`add_header` does not merge.** It is an array directive. The moment a `location` declares its own `add_header`, every server-level header disappears *in that location*. You ship a page without `X-Frame-Options` and the scan only flags one route.

**`if` is a configuration context.** Only `return`, `rewrite` and `set` are reliable inside it. A `proxy_pass` inside `if` is the classic "sometimes I get the wrong upstream" bug.

**`alias` is a prefix replacement, not a concatenation.** `location /static { alias /srv/static; }` serves `/srv/staticapp.css` for `/static/app.css`.

**TLS defaults are whatever your build was compiled with.** Publishing a service on `443 ssl` without `ssl_protocols` is not "secure by default", it is "secure by whatever version of OpenSSL you linked".

These are the findings that cost hours in production and seconds to see in review — if something points at the line.

## Install

No dependencies. Python 3.9+.

```bash
pip install git+https://github.com/aiplusplus360/nginx-doctor
```

## Usage

```bash
nginx-doctor /etc/nginx                    # every *.conf under a directory
nginx-doctor deploy/nginx.conf             # one file
nginx-doctor . --format json
nginx-doctor . --fail-on high              # CI gate
nginx-doctor --explain proxy-uri-slash-mismatch
```

Exit codes: `0` clean, `1` findings at or above `--fail-on` (default `high`), `2` a config that cannot be parsed.

## What it checks

| Code | Severity | The trap |
| --- | --- | --- |
| `proxy-uri-slash-mismatch` | high | Prefix and proxy URI disagree about the trailing slash |
| `proxy-pass-uri-with-request-uri` | high | A URI part plus `$request_uri` duplicates the prefix |
| `proxy-pass-inside-if` | high | `proxy_pass` in a context nginx does not support it in |
| `proxy-pass-variable-without-resolver` | error | Variable upstream with no `resolver` |
| `add-header-shadowing` | high | A nested `add_header` drops inherited headers |
| `if-non-rewrite` | medium | `if` containing anything but `return`/`rewrite`/`set` |
| `alias-without-trailing-slash` | high | `alias` prefix replacement without the slash |
| `root-and-alias` | error | Both set on the same location |
| `try-files-loop` | high | Fallback re-enters its own location |
| `try-files-relative-fallback` | medium | Relative fallback resolves inside the prefix |
| `location-without-handler` | medium | Location that falls through to the parent |
| `duplicate-server-name` | high | Second block silently never answers |
| `server-without-name` | high | Block only reachable as the default server |
| `server-without-listen` | high | Block that is never reached |
| `ssl-without-certificate` | error | `ssl` on `listen` with no certificate |
| `certificate-without-key` | error | Certificate that cannot be used |
| `weak-tls-version` | high | `SSLv3`/`TLSv1`/`TLSv1.1` enabled |
| `tls-defaults` | medium | TLS server relying on build defaults |
| `proxy-host-header` | medium | No explicit `Host` header to the backend |
| `missing-forwarded-proto` | medium | TLS terminated but the app never told |

## The parser

nginx config is not YAML and not JSON. It is `directive arg arg;` with optional `{ }` blocks, quoted arguments that may contain `#`, escapes inside double quotes, and comments. The parser here is ~120 lines, produces a tree with file/line on every node, and raises a located `ConfigError` rather than guessing:

```console
$ nginx-doctor broken.conf
nginx-doctor: broken.conf:14: directive 'proxy_pass' is not terminated
```

That is deliberate. A linter that silently mis-parses is worse than no linter, because the absence of findings reads as approval.

## Library use

```python
from nginxdoctor import parse, lint

tree = parse(open("nginx.conf").read(), "nginx.conf")
for finding in lint(tree):
    print(f"{finding.file}:{finding.line} {finding.severity} {finding.code}")
```

## Tests

```bash
python -m unittest discover -s tests -v
```

41 tests. Each rule has a positive fixture and a negative one, so a rule that starts firing on correct configuration fails the build. `examples/good.conf` is a real configuration that must produce **no** high findings; `examples/bad.conf` contains seven planted bugs and the suite asserts each is found.
