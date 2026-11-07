import os
import tempfile
import unittest

from nginxdoctor.core import (
    ConfigError,
    lint,
    parse,
    parse_file,
    severity_at_least,
)

GOOD = "examples/good.conf"
BAD = "examples/bad.conf"


def codes(config, filename="t.conf"):
    return [f.code for f in lint(parse(config, filename), filename)]


class TokenizerTests(unittest.TestCase):
    def test_comments_are_ignored(self):
        tree = parse("# a comment\nserver { listen 80; }\n")
        self.assertEqual(tree[0].name, "server")

    def test_quoted_arguments_keep_spaces(self):
        tree = parse('add_header X-Note "hello world";')
        self.assertEqual(tree[0].args, ["X-Note", "hello world"])

    def test_escaped_quote_inside_string(self):
        tree = parse('add_header X-Note "a \\" b";')
        self.assertEqual(tree[0].args, ["X-Note", 'a " b'])

    def test_hash_inside_quotes_is_not_a_comment(self):
        tree = parse('add_header X-Note "a#b";')
        self.assertEqual(tree[0].args, ["X-Note", "a#b"])

    def test_line_numbers_survive_multiline_blocks(self):
        tree = parse("server {\n  listen 80;\n  location / {\n    root /srv;\n  }\n}\n")
        server = tree[0]
        self.assertEqual(server.line, 1)
        self.assertEqual(server.children("location")[0].line, 3)

    def test_unterminated_directive_is_an_error(self):
        with self.assertRaises(ConfigError):
            parse("server { listen 80 }")

    def test_unterminated_block_is_an_error(self):
        with self.assertRaises(ConfigError):
            parse("server { listen 80;")

    def test_stray_closing_brace_is_an_error(self):
        with self.assertRaises(ConfigError):
            parse("server { } }")

    def test_unterminated_quote_is_an_error(self):
        with self.assertRaises(ConfigError):
            parse('add_header X "unterminated;')


class ProxyRules(unittest.TestCase):
    def test_trailing_slash_mismatch_is_flagged(self):
        config = "server{server_name a;listen 80;location /api{proxy_pass http://x/;}}"
        self.assertIn("proxy-uri-slash-mismatch", codes(config))

    def test_matching_slashes_are_not_flagged(self):
        config = "server{server_name a;listen 80;location /api/{proxy_pass http://x/;}}"
        self.assertNotIn("proxy-uri-slash-mismatch", codes(config))

    def test_proxy_without_uri_is_not_flagged(self):
        config = "server{server_name a;listen 80;location /api{proxy_pass http://x;}}"
        self.assertNotIn("proxy-uri-slash-mismatch", codes(config))

    def test_proxy_inside_if_is_flagged(self):
        config = (
            "server{server_name a;listen 80;location /{"
            "if ($x = 1){proxy_pass http://x;} }}"
        )
        self.assertIn("proxy-pass-inside-if", codes(config))

    def test_variable_upstream_needs_resolver(self):
        config = "server{server_name a;listen 80;location /{proxy_pass http://$b;}}"
        self.assertIn("proxy-pass-variable-without-resolver", codes(config))

    def test_resolver_satisfies_variable_upstream(self):
        config = (
            "http{server{server_name a;listen 80;resolver 127.0.0.53;"
            "location /{proxy_pass http://$b;}}}"
        )
        self.assertNotIn("proxy-pass-variable-without-resolver", codes(config))

    def test_missing_host_header_is_flagged(self):
        config = "server{server_name a;listen 80;location /{proxy_pass http://x;}}"
        self.assertIn("proxy-host-header", codes(config))

    def test_host_header_silences_the_rule(self):
        config = (
            "server{server_name a;listen 80;location /{proxy_pass http://x;"
            "proxy_set_header Host $host;}}"
        )
        self.assertNotIn("proxy-host-header", codes(config))

    def test_tls_proxy_without_forwarded_proto_is_flagged(self):
        config = (
            "server{server_name a;listen 443 ssl;ssl_certificate c;"
            "ssl_certificate_key k;ssl_protocols TLSv1.2;"
            "location /{proxy_pass http://x;proxy_set_header Host $host;}}"
        )
        self.assertIn("missing-forwarded-proto", codes(config))

    def test_uri_plus_request_uri_is_flagged(self):
        config = (
            "server{server_name a;listen 80;location /api/{"
            "proxy_pass http://x/base$request_uri;}}"
        )
        self.assertIn("proxy-pass-uri-with-request-uri", codes(config))


class HeaderRules(unittest.TestCase):
    def test_nested_add_header_shadows_server_headers(self):
        config = (
            "server{server_name a;listen 80;add_header X-A 1;"
            "location /s/{root /srv;add_header X-B 2;}}"
        )
        self.assertIn("add-header-shadowing", codes(config))

    def test_single_level_add_header_is_fine(self):
        config = "server{server_name a;listen 80;add_header X-A 1;location /{root /srv;}}"
        self.assertNotIn("add-header-shadowing", codes(config))


class ServerRules(unittest.TestCase):
    def test_duplicate_server_name_is_flagged(self):
        config = (
            "http{server{server_name a.com;listen 80;location /{root /a;}}"
            "server{server_name a.com;listen 80;location /{root /b;}}}"
        )
        self.assertIn("duplicate-server-name", codes(config))

    def test_same_name_on_different_ports_is_allowed(self):
        config = (
            "http{server{server_name a.com;listen 80;location /{root /a;}}"
            "server{server_name a.com;listen 81;location /{root /b;}}}"
        )
        self.assertNotIn("duplicate-server-name", codes(config))

    def test_missing_server_name_is_flagged(self):
        config = "server{listen 80;location /{root /a;}}"
        self.assertIn("server-without-name", codes(config))

    def test_missing_listen_is_flagged(self):
        config = "server{server_name a;location /{root /a;}}"
        self.assertIn("server-without-listen", codes(config))

    def test_weak_tls_version_is_flagged(self):
        config = (
            "server{server_name a;listen 443 ssl;ssl_certificate c;"
            "ssl_certificate_key k;ssl_protocols TLSv1 TLSv1.2;"
            "location /{root /s;}}"
        )
        self.assertIn("weak-tls-version", codes(config))

    def test_ssl_without_certificate_is_an_error(self):
        config = "server{server_name a;listen 443 ssl;location /{root /s;}}"
        findings = lint(parse(config))
        errors = [f for f in findings if f.code == "ssl-without-certificate"]
        self.assertEqual(errors[0].severity, "error")

    def test_certificate_without_key_is_flagged(self):
        config = (
            "server{server_name a;listen 443 ssl;ssl_certificate c;"
            "ssl_protocols TLSv1.2;location /{root /s;}}"
        )
        self.assertIn("certificate-without-key", codes(config))


class LocationRules(unittest.TestCase):
    def test_alias_without_trailing_slash_is_flagged(self):
        config = "server{server_name a;listen 80;location /static{alias /srv/static;}}"
        self.assertIn("alias-without-trailing-slash", codes(config))

    def test_root_and_alias_together_is_an_error(self):
        config = "server{server_name a;listen 80;location /s/{root /a;alias /b/;}}"
        findings = lint(parse(config))
        matches = [f for f in findings if f.code == "root-and-alias"]
        self.assertEqual(matches[0].severity, "error")

    def test_location_without_handler_is_flagged(self):
        config = "server{server_name a;listen 80;location /static/{}}"
        self.assertIn("location-without-handler", codes(config))

    def test_try_files_loop_is_flagged(self):
        config = (
            "server{server_name a;listen 80;location /app/{"
            "try_files $uri /app/index.html;}}"
        )
        self.assertIn("try-files-loop", codes(config))

    def test_try_files_404_is_fine(self):
        config = "server{server_name a;listen 80;location /app/{try_files $uri =404;}}"
        self.assertNotIn("try-files-loop", codes(config))

    def test_relative_try_files_fallback_is_flagged(self):
        config = "server{server_name a;listen 80;location /a/{try_files $uri fallback.html;}}"
        self.assertIn("try-files-relative-fallback", codes(config))


class IfRules(unittest.TestCase):
    def test_if_with_proxy_is_flagged(self):
        config = "server{server_name a;listen 80;location /{if ($x){proxy_pass http://y;}}}"
        self.assertIn("if-non-rewrite", codes(config))

    def test_if_with_return_is_fine(self):
        config = "server{server_name a;listen 80;location /{if ($x){return 403;}}}"
        self.assertNotIn("if-non-rewrite", codes(config))


class ExampleFixtureTests(unittest.TestCase):
    def test_bad_example_reports_the_planted_bugs(self):
        findings = lint(parse_file(BAD), BAD)
        reported = {f.code for f in findings}
        for expected in (
            "duplicate-server-name",
            "proxy-uri-slash-mismatch",
            "add-header-shadowing",
            "ssl-without-certificate",
            "weak-tls-version",
            "proxy-pass-variable-without-resolver",
            "proxy-pass-inside-if",
        ):
            self.assertIn(expected, reported, expected)
        self.assertTrue(any(f.severity == "error" for f in findings))

    def test_good_example_has_no_high_findings(self):
        findings = lint(parse_file(GOOD), GOOD)
        high = [f for f in findings if severity_at_least(f.severity, "high")]
        self.assertEqual(high, [], [str(f) for f in high])

    def test_findings_carry_the_right_line_numbers(self):
        findings = lint(parse_file(BAD), BAD)
        mismatch = [f for f in findings if f.code == "proxy-uri-slash-mismatch"]
        self.assertEqual(len(mismatch), 1, mismatch)
        with open(BAD, encoding="utf-8") as handle:
            line = handle.read().splitlines()
        self.assertIn("proxy_pass http://app/;", line[mismatch[0].line - 1])

    def test_findings_are_sorted_by_severity(self):
        findings = lint(parse_file(BAD), BAD)
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "error": 4}
        ranks = [order[f.severity] for f in findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


class FileHandlingTests(unittest.TestCase):
    def test_parse_file_reads_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "c.conf")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# caf\u00e9\nserver { listen 80; }\n")
            tree = parse_file(path)
            self.assertEqual(tree[0].name, "server")


if __name__ == "__main__":
    unittest.main()
