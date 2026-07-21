import argparse
import hashlib
import http.server
import io
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import check
from check import ProbeResult, _fetch_robots, _looks_like_baseline, _request
from check import evaluate_robots, evaluate_robots_response


class RobotsContentTests(unittest.TestCase):
    def allowed(self, rules, agent="GPTBot", key="root_allowed"):
        return evaluate_robots(rules, [agent])[agent][key]

    def test_specific_agent_overrides_wildcard(self):
        rules = "User-agent: *\nAllow: /\n\nUser-agent: GPTBot\nDisallow: /\n"
        self.assertFalse(self.allowed(rules))
        self.assertTrue(self.allowed(rules, "ClaudeBot"))

    def test_directives_and_agent_names_are_case_insensitive(self):
        rules = "uSeR-aGeNt: gPtBoT\ndIsAlLoW: /\n"
        self.assertFalse(self.allowed(rules, "GPTBOT/1.0"))

    def test_bom_crlf_comments_and_unknown_directives(self):
        rules = ("\ufeff# file comment\r\nUser-agent: GPTBot # inline\r\n"
                 "Crawl-delay: 10\r\nSitemap: https://example.test/map.xml\r\n"
                 "Disallow: / # everything\r\n")
        self.assertFalse(self.allowed(rules))

    def test_multiple_agents_share_a_group(self):
        rules = "User-agent: GPTBot\nUser-agent: ClaudeBot\nDisallow: /\n"
        self.assertFalse(self.allowed(rules, "GPTBot"))
        self.assertFalse(self.allowed(rules, "ClaudeBot"))

    def test_repeated_groups_for_same_agent_are_combined(self):
        rules = ("User-agent: GPTBot\nDisallow: /private\n\n"
                 "User-agent: GPTBot\nDisallow: /secret\n")
        policies = check._robots_groups(rules)
        self.assertFalse(check._can_fetch(policies, "GPTBot", "/private/a"))
        self.assertFalse(check._can_fetch(policies, "GPTBot", "/secret/a"))

    def test_empty_disallow_allows(self):
        self.assertTrue(self.allowed("User-agent: GPTBot\nDisallow:\n"))

    def test_empty_and_malformed_files_allow(self):
        for rules in ("", "nonsense\nwithout: a user agent\n", "# comment only\n"):
            with self.subTest(rules=rules):
                self.assertTrue(self.allowed(rules))

    def test_allow_can_override_broader_disallow(self):
        groups = check._robots_groups(
            "User-agent: GPTBot\nDisallow: /\nAllow: /public/\n"
        )
        self.assertTrue(check._can_fetch(groups, "GPTBot", "/public/page"))
        self.assertFalse(check._can_fetch(groups, "GPTBot", "/private/page"))

    def test_allow_wins_equal_length_tie(self):
        groups = check._robots_groups(
            "User-agent: GPTBot\nDisallow: /same\nAllow: /same\n"
        )
        self.assertTrue(check._can_fetch(groups, "GPTBot", "/same"))

    def test_wildcard_and_end_anchor(self):
        groups = check._robots_groups(
            "User-agent: GPTBot\nDisallow: /*.zip$\n"
        )
        self.assertFalse(check._can_fetch(groups, "GPTBot", "/files/a.zip"))
        self.assertTrue(check._can_fetch(groups, "GPTBot", "/files/a.zip?download=1"))

    def test_query_string_can_be_matched(self):
        groups = check._robots_groups(
            "User-agent: GPTBot\nDisallow: /*?preview=\n"
        )
        self.assertFalse(check._can_fetch(groups, "GPTBot", "/item?preview=1"))
        self.assertTrue(check._can_fetch(groups, "GPTBot", "/item?view=1"))

    def test_robots_path_is_evaluated_separately(self):
        rules = "User-agent: GPTBot\nDisallow: /\nAllow: /robots.txt\n"
        result = evaluate_robots(rules, ["GPTBot"])["GPTBot"]
        self.assertFalse(result["root_allowed"])
        self.assertTrue(result["robots_allowed"])

    def test_no_matching_group_defaults_to_allow(self):
        self.assertTrue(self.allowed("User-agent: OtherBot\nDisallow: /\n"))

    def test_partial_restriction_is_reported_when_root_is_allowed(self):
        result = evaluate_robots(
            "User-agent: GPTBot\nDisallow: /private\n", ["GPTBot"], ["/private/a"]
        )["GPTBot"]
        self.assertTrue(result["root_allowed"])
        self.assertTrue(result["declares_disallow"])
        self.assertEqual(result["disallow_patterns"], ["/private"])
        self.assertFalse(result["paths"]["/private/a"])

    def test_unicode_path(self):
        groups = check._robots_groups("User-agent: GPTBot\nDisallow: /פרטי\n")
        self.assertFalse(check._can_fetch(groups, "GPTBot", "/פרטי/1"))

    def test_percent_encoded_utf8_and_unreserved_octets_match(self):
        groups = check._robots_groups(
            "User-agent: GPTBot\nDisallow: /caf%C3%A9\nDisallow: /~user\n"
        )
        self.assertFalse(check._can_fetch(groups, "GPTBot", "/café/menu"))
        self.assertFalse(check._can_fetch(groups, "GPTBot", "/%7Euser/profile"))

    def test_paths_are_case_sensitive(self):
        groups = check._robots_groups("User-agent: GPTBot\nDisallow: /Private\n")
        self.assertFalse(check._can_fetch(groups, "GPTBot", "/Private/a"))
        self.assertTrue(check._can_fetch(groups, "GPTBot", "/private/a"))


class RobotsResponseTests(unittest.TestCase):
    def test_success_evaluates_rules(self):
        state, result = evaluate_robots_response(
            200, "User-agent: GPTBot\nDisallow: /\n", ["GPTBot"]
        )
        self.assertEqual(state, "rules_evaluated")
        self.assertFalse(result["GPTBot"]["root_allowed"])

    def test_all_success_statuses_are_parsed(self):
        state, result = evaluate_robots_response(204, "", ["GPTBot"])
        self.assertEqual(state, "rules_evaluated")
        self.assertTrue(result["GPTBot"]["root_allowed"])

    def test_redirect_is_reported_unknown(self):
        state, result = evaluate_robots_response(301, "", ["GPTBot"])
        self.assertEqual(state, "redirect_unresolved_unknown")
        self.assertEqual(result, {})

    def test_4xx_is_unavailable_and_allows_per_rfc_9309(self):
        for status in (400, 401, 403, 404, 429):
            with self.subTest(status=status):
                state, result = evaluate_robots_response(status, "", ["GPTBot"])
                self.assertEqual(state, "unavailable_allow")
                self.assertTrue(result["GPTBot"]["root_allowed"])

    def test_5xx_is_unreachable_and_disallows_per_rfc_9309(self):
        for status in (500, 502, 503, 599):
            with self.subTest(status=status):
                state, result = evaluate_robots_response(status, "", ["GPTBot"])
                self.assertEqual(state, "unreachable_disallow")
                self.assertFalse(result["GPTBot"]["root_allowed"])

    def test_network_error_is_unknown(self):
        state, result = evaluate_robots_response(None, "", ["GPTBot"], "timeout")
        self.assertEqual(state, "request_failed_unknown")
        self.assertEqual(result, {})


class SummaryTests(unittest.TestCase):
    def policy(self, *, root=True, disallow=False, paths=None):
        return {
            "root_allowed": root,
            "robots_allowed": True,
            "declares_disallow": disallow,
            "allow_patterns": [],
            "disallow_patterns": ["/private"] if disallow else [],
            "paths": {"/": root, "/robots.txt": True, **(paths or {})},
        }

    def probe(self, name, accepted=None, *, status=200, error=""):
        return ProbeResult(name, "example.test", "example.test", status=status,
                           error=error, accepted_like_baseline=accepted)

    def test_bot_access_summary(self):
        cases = [
            ({}, "Unknown"),
            ({"GPTBot": self.policy()}, "Yes"),
            ({"GPTBot": self.policy(disallow=True)}, "Partially"),
            ({"GPTBot": self.policy(root=False)}, "No"),
            ({"GPTBot": self.policy(paths={"/private": False})}, "Partially"),
        ]
        for policies, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(check._bot_access_summary(policies), expected)

    def test_probe_validation_summary(self):
        baseline = self.probe("baseline")
        cases = [
            ([self.probe("baseline", status=None)], "random_host", "Unknown"),
            ([baseline], "random_host_and_sni", "Not applicable"),
            ([baseline, self.probe("random_host", False)], "random_host", "Yes"),
            ([baseline, self.probe("random_host_and_sni", True)],
             "random_host_and_sni", "No"),
        ]
        for probes, name, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(check._probe_validation_summary(probes, name), expected)

    def test_partial_report_explains_rules_and_risk(self):
        policy = self.policy(disallow=True)
        report = {
            "summary": {
                "bots_allowed": "Partially",
                "server_checks_hostname_sni": "Yes",
            },
            "target": "https://example.test/",
            "robots": {
                "url": "https://example.test/robots.txt",
                "status": 200,
                "interpretation": "rules_evaluated",
                "error": "",
                "fetch_chain": [],
                "agents": {"GPTBot": policy, "ClaudeBot": policy},
            },
            "probes": [{
                "name": "baseline", "accepted_like_baseline": None,
                "error": "", "status": 200, "content_type": "text/html",
                "body_bytes": 100,
            }],
        }
        output = io.StringIO()
        with redirect_stdout(output):
            check._print_report(report)
        rendered = output.getvalue()
        self.assertTrue(rendered.startswith(
            "Bots allowed to access? Partially\nServer checks hostname/SNI? Yes"
        ))
        self.assertIn("Consequences", rendered)
        self.assertIn("Partial robots.txt rules:", rendered)
        self.assertIn("GPTBot, ClaudeBot", rendered)
        self.assertIn("Disallow: /private", rendered)

        report["summary"] = {
            "bots_allowed": "No",
            "server_checks_hostname_sni": "No",
        }
        output = io.StringIO()
        with redirect_stdout(output):
            check._print_report(report)
        self.assertIn("Even with robots.txt, bots that ignore TLS certificate "
                      "mismatches could be manipulated to DoS this site.",
                      output.getvalue())


class ComparisonTests(unittest.TestCase):
    def result(self, **changes):
        values = dict(name="x", sni="example.test", host_header="example.test",
                      status=200, content_type="text/html", body_bytes=1000,
                      body_sha256=hashlib.sha256(b"body").hexdigest(), error="")
        values.update(changes)
        return ProbeResult(**values)

    def test_exact_response_is_equivalent(self):
        self.assertTrue(_looks_like_baseline(self.result(), self.result()))

    def test_small_dynamic_length_change_is_equivalent(self):
        self.assertTrue(_looks_like_baseline(
            self.result(body_bytes=1049, body_sha256="different"), self.result()
        ))

    def test_material_response_differences_are_rejected(self):
        baseline = self.result()
        for probe in (self.result(status=421), self.result(content_type="text/plain"),
                      self.result(body_bytes=1200, body_sha256="different"),
                      self.result(error="TLS failure")):
            with self.subTest(probe=probe):
                self.assertFalse(_looks_like_baseline(probe, baseline))

    def test_https_audit_keeps_host_and_sni_consistent(self):
        calls = []

        def fake_request(**kwargs):
            calls.append(kwargs)
            result = ProbeResult(kwargs["name"], kwargs["sni"], kwargs["host_header"],
                                 status=404, content_type="text/plain",
                                 body_sha256=hashlib.sha256(b"").hexdigest())
            return result, b""

        args = argparse.Namespace(url="https://example.test/path", timeout=1,
                                  agent=["GPTBot"], path=[], max_redirects=5)
        with patch.object(check, "_request", side_effect=fake_request):
            report = check.audit(args)
        self.assertEqual([call["name"] for call in calls],
                         ["baseline", "random_host_and_sni", "robots.txt"])
        self.assertEqual(calls[1]["sni"], calls[1]["host_header"])
        self.assertNotEqual(calls[1]["sni"], "example.test")
        self.assertEqual(report["robots"]["interpretation"], "unavailable_allow")

    def test_http_audit_skips_sni_cases(self):
        calls = []

        def fake_request(**kwargs):
            calls.append(kwargs)
            return ProbeResult(kwargs["name"], kwargs["sni"], kwargs["host_header"],
                               status=200, body_sha256=hashlib.sha256(b"").hexdigest()), b""

        args = argparse.Namespace(url="http://example.test/", timeout=1,
                                  agent=["GPTBot"], path=[], max_redirects=5)
        with patch.object(check, "_request", side_effect=fake_request):
            check.audit(args)
        self.assertEqual([call["name"] for call in calls],
                         ["baseline", "random_host", "robots.txt"])


class RedirectTests(unittest.TestCase):
    def response(self, status, location="", error=""):
        return ProbeResult("robots.txt", "example.test", "example.test",
                           status=status, location=location, error=error)

    def test_follows_relative_redirect(self):
        with patch.object(check, "_request", side_effect=[
            (self.response(301, "/canonical-robots.txt"), b""),
            (self.response(200), b"User-agent: *\nAllow: /\n"),
        ]) as request:
            result, body, chain = _fetch_robots(
                "https://example.test/robots.txt", 1, 5
            )
        self.assertEqual(result.status, 200)
        self.assertIn(b"User-agent", body)
        self.assertEqual(request.call_args_list[1].kwargs["path"],
                         "/canonical-robots.txt")
        self.assertEqual(len(chain), 2)

    def test_follows_redirect_to_canonical_hostname(self):
        with patch.object(check, "_request", side_effect=[
            (self.response(301, "https://www.example.test/robots.txt"), b""),
            (self.response(200), b""),
        ]) as request:
            _fetch_robots("https://example.test/robots.txt", 1, 5)
        second = request.call_args_list[1].kwargs
        self.assertEqual(second["connect_host"], "www.example.test")
        self.assertEqual(second["sni"], "www.example.test")
        self.assertEqual(second["host_header"], "www.example.test")

    def test_detects_redirect_loop(self):
        with patch.object(check, "_request", return_value=(
            self.response(301, "/robots.txt"), b""
        )):
            result, _body, chain = _fetch_robots(
                "https://example.test/robots.txt", 1, 5
            )
        self.assertEqual(result.error, "redirect loop detected")
        self.assertEqual(len(chain), 1)

    def test_enforces_redirect_limit(self):
        with patch.object(check, "_request", return_value=(
            self.response(301, "/next"), b""
        )):
            result, _body, chain = _fetch_robots(
                "https://example.test/robots.txt", 1, 0
            )
        self.assertEqual(result.error, "redirect limit exceeded (0)")
        self.assertEqual(len(chain), 1)


class ArgumentsTests(unittest.TestCase):
    def test_obsolete_acknowledgement_flag_is_absent_from_project(self):
        obsolete = "--ack-" + "authorized"
        root = Path(__file__).parent.parent
        for path in root.rglob("*"):
            if path.suffix in (".py", ".md", ".html") and ".venv" not in path.parts:
                with self.subTest(path=path):
                    self.assertNotIn(obsolete, path.read_text(encoding="utf-8"))


class LocalNetworkTests(unittest.TestCase):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = self.headers["Host"].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    def test_request_sends_selected_host_header(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result, body = _request(
                connect_host="127.0.0.1", port=server.server_port, scheme="http",
                sni=None, host_header="random.invalid", path="/", timeout=2,
                name="test",
            )
            self.assertEqual(result.status, 200)
            self.assertEqual(body, b"random.invalid")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    @unittest.skipUnless(shutil.which("openssl"), "openssl is required for local TLS test")
    def test_server_can_reject_unexpected_sni(self):
        with tempfile.TemporaryDirectory() as directory:
            cert = Path(directory) / "cert.pem"
            key = Path(directory) / "key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "1", "-subj", "/CN=localhost", "-keyout", str(key),
                "-out", str(cert),
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self.Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)

            def validate_sni(_socket, name, _context):
                if name != "localhost":
                    return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME

            context.set_servername_callback(validate_sni)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                accepted, _ = _request(
                    connect_host="127.0.0.1", port=server.server_port, scheme="https",
                    sni="localhost", host_header="localhost", path="/", timeout=2,
                    name="accepted",
                )
                rejected, _ = _request(
                    connect_host="127.0.0.1", port=server.server_port, scheme="https",
                    sni="random.invalid", host_header="localhost", path="/", timeout=2,
                    name="rejected",
                )
                self.assertEqual(accepted.status, 200)
                self.assertIn("SSLError", rejected.error)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()


if __name__ == "__main__":
    unittest.main()
