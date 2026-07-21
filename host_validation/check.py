#!/usr/bin/env python3
"""Audit robots.txt and virtual-host validation on a target host."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import socket
import ssl
import sys
from dataclasses import asdict, dataclass
from http.client import HTTPResponse
from urllib.parse import urljoin, urlsplit, urlunsplit

DEFAULT_AGENTS = ("GPTBot", "OAI-SearchBot", "ChatGPT-User", "ClaudeBot")
MAX_RESPONSE_BYTES = 1024 * 1024
REDIRECT_STATUSES = frozenset((301, 302, 303, 307, 308))
UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


@dataclass
class ProbeResult:
    name: str
    sni: str | None
    host_header: str
    status: int | None = None
    content_type: str = ""
    body_bytes: int = 0
    body_sha256: str = ""
    error: str = ""
    location: str = ""
    accepted_like_baseline: bool | None = None


def _request(
    *, connect_host: str, port: int, scheme: str, sni: str | None,
    host_header: str, path: str, timeout: float, name: str,
) -> tuple[ProbeResult, bytes]:
    result = ProbeResult(name=name, sni=sni, host_header=host_header)
    sock: socket.socket | ssl.SSLSocket | None = None
    try:
        sock = socket.create_connection((connect_host, port), timeout=timeout)
        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=sni)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: ai-bot-exposure-audit/1.0\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        sock.sendall(request)
        response = HTTPResponse(sock)
        response.begin()
        body = response.read(MAX_RESPONSE_BYTES)
        result.status = response.status
        result.content_type = response.getheader("Content-Type", "").split(";", 1)[0]
        result.location = response.getheader("Location", "")
        result.body_bytes = len(body)
        result.body_sha256 = hashlib.sha256(body).hexdigest()
        return result, body
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        return result, b""
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _looks_like_baseline(probe: ProbeResult, baseline: ProbeResult) -> bool:
    if probe.error or baseline.error or probe.status != baseline.status:
        return False
    if probe.content_type != baseline.content_type:
        return False
    if probe.body_sha256 == baseline.body_sha256:
        return True
    tolerance = max(64, int(baseline.body_bytes * 0.05))
    return abs(probe.body_bytes - baseline.body_bytes) <= tolerance


def _fetch_robots(url: str, timeout: float, max_redirects: int
                  ) -> tuple[ProbeResult, bytes, list[dict]]:
    """Fetch robots.txt and follow bounded HTTP(S) redirects."""
    current = url
    seen: set[str] = set()
    chain: list[dict] = []
    result = ProbeResult("robots.txt", None, "")
    body = b""

    for redirect_count in range(max_redirects + 1):
        parsed = urlsplit(current)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            result.error = f"invalid redirect URL: {current}"
            break
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        display_host = f"[{hostname}]" if ":" in hostname else hostname
        host_header = display_host if port in (80, 443) else f"{display_host}:{port}"
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        result, body = _request(
            connect_host=hostname, port=port, scheme=parsed.scheme,
            sni=hostname, host_header=host_header, path=path,
            timeout=timeout, name="robots.txt",
        )
        chain.append({
            "url": current,
            "status": result.status,
            "location": result.location,
            "error": result.error,
        })
        if result.error or result.status not in REDIRECT_STATUSES:
            break
        if not result.location:
            break
        if redirect_count >= max_redirects:
            result.error = f"redirect limit exceeded ({max_redirects})"
            chain[-1]["error"] = result.error
            break
        destination = urljoin(current, result.location)
        if destination in seen or destination == current:
            result.error = "redirect loop detected"
            chain[-1]["error"] = result.error
            break
        seen.add(current)
        current = destination
    return result, body, chain


def _robots_groups(text: str) -> list[tuple[list[str], list[tuple[bool, str]]]]:
    """Parse robots groups while ignoring unknown directives."""
    groups: list[tuple[list[str], list[tuple[bool, str]]]] = []
    user_agents: list[str] = []
    rules: list[tuple[bool, str]] = []
    saw_rule = False

    for raw_line in text.removeprefix("\ufeff").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, value = (part.strip() for part in line.split(":", 1))
        field = field.casefold()
        if field == "user-agent":
            if saw_rule and user_agents:
                groups.append((user_agents, rules))
                user_agents, rules, saw_rule = [], [], False
            if value:
                user_agents.append(value.casefold())
        elif field in ("allow", "disallow") and user_agents:
            saw_rule = True
            # An empty Disallow has no effect; the same is true for Allow.
            if value:
                rules.append((field == "allow", value))
    if user_agents:
        groups.append((user_agents, rules))
    return groups


def _normalize_robot_path(value: str) -> str:
    """Normalize percent encoding for RFC 9309-style octet comparison."""
    output: list[str] = []
    index = 0
    while index < len(value):
        if (value[index] == "%" and index + 2 < len(value)
                and all(char in "0123456789abcdefABCDEF" for char in value[index + 1:index + 3])):
            byte = int(value[index + 1:index + 3], 16)
            char = chr(byte)
            output.append(char if char in UNRESERVED else f"%{byte:02X}")
            index += 3
            continue
        char = value[index]
        if ord(char) > 127:
            output.extend(f"%{byte:02X}" for byte in char.encode("utf-8"))
        else:
            output.append(char)
        index += 1
    return "".join(output)


def _rule_matches(pattern: str, path: str) -> bool:
    pattern = _normalize_robot_path(pattern)
    path = _normalize_robot_path(path)
    anchored = pattern.endswith("$")
    if anchored:
        pattern = pattern[:-1]
    expression = re.escape(pattern).replace(r"\*", ".*")
    return re.match("^" + expression + ("$" if anchored else ""), path) is not None


def _applicable_rules(groups: list[tuple[list[str], list[tuple[bool, str]]]],
                      agent: str) -> list[tuple[bool, str]]:
    name = agent.casefold()
    matches: list[tuple[int, list[tuple[bool, str]]]] = []
    for names, rules in groups:
        lengths = [0 if token == "*" else len(token)
                   for token in names if token == "*" or token in name]
        if lengths:
            matches.append((max(lengths), rules))
    if not matches:
        return []
    specificity = max(length for length, _ in matches)
    return [rule for length, rules in matches if length == specificity for rule in rules]


def _can_fetch(groups: list[tuple[list[str], list[tuple[bool, str]]]],
               agent: str, path: str) -> bool:
    applicable = _applicable_rules(groups, agent)
    matching = [(len(pattern.rstrip("$")), allowed)
                for allowed, pattern in applicable if _rule_matches(pattern, path)]
    if not matching:
        return True
    longest = max(length for length, _ in matching)
    return any(allowed for length, allowed in matching if length == longest)


def evaluate_robots(text: str, agents: list[str],
                    paths: list[str] | None = None) -> dict[str, dict]:
    groups = _robots_groups(text)
    checked_paths = list(dict.fromkeys(["/", "/robots.txt", *(paths or [])]))
    policies = {}
    for agent in agents:
        applicable = _applicable_rules(groups, agent)
        policies[agent] = {
            "root_allowed": _can_fetch(groups, agent, "/"),
            "robots_allowed": _can_fetch(groups, agent, "/robots.txt"),
            "declares_disallow": any(not allowed for allowed, _ in applicable),
            "allow_patterns": [pattern for allowed, pattern in applicable if allowed],
            "disallow_patterns": [pattern for allowed, pattern in applicable
                                  if not allowed],
            "paths": {path: _can_fetch(groups, agent, path) for path in checked_paths},
        }
    return policies


def evaluate_robots_response(status: int | None, text: str, agents: list[str],
                             error: str = "", paths: list[str] | None = None
                             ) -> tuple[str, dict]:
    """Apply RFC 9309 availability semantics to a robots response."""
    if error or status is None:
        return "request_failed_unknown", {}
    if 200 <= status < 300:
        return "rules_evaluated", evaluate_robots(text, agents, paths)
    if 300 <= status < 400:
        return "redirect_unresolved_unknown", {}
    if 400 <= status < 500:
        checked_paths = list(dict.fromkeys(["/", "/robots.txt", *(paths or [])]))
        allowed = {"root_allowed": True, "robots_allowed": True,
                   "declares_disallow": False,
                   "allow_patterns": [], "disallow_patterns": [],
                   "paths": {path: True for path in checked_paths}}
        return "unavailable_allow", {agent: allowed.copy() for agent in agents}
    if 500 <= status < 600:
        checked_paths = list(dict.fromkeys(["/", "/robots.txt", *(paths or [])]))
        blocked = {"root_allowed": False, "robots_allowed": False,
                   "declares_disallow": True,
                   "allow_patterns": [], "disallow_patterns": [],
                   "paths": {path: False for path in checked_paths}}
        return "unreachable_disallow", {agent: blocked.copy() for agent in agents}
    return "unexpected_status_unknown", {}


def _bot_access_summary(policies: dict[str, dict]) -> str:
    if not policies:
        return "Unknown"
    allowed = [value for policy in policies.values()
               for path, value in policy["paths"].items() if path != "/robots.txt"]
    if not allowed:
        return "Unknown"
    if all(allowed) and not any(policy["declares_disallow"]
                                for policy in policies.values()):
        return "Yes"
    if not any(allowed):
        return "No"
    return "Partially"


def _probe_validation_summary(probes: list[ProbeResult], name: str) -> str:
    baseline = next((probe for probe in probes if probe.name == "baseline"), None)
    if baseline is None or baseline.error or baseline.status is None:
        return "Unknown"
    probe = next((probe for probe in probes if probe.name == name), None)
    if probe is None:
        return "Not applicable"
    if probe.accepted_like_baseline is None:
        return "Unknown"
    return "No" if probe.accepted_like_baseline else "Yes"


def _policy_rule_groups(
    policies: dict[str, dict],
) -> list[tuple[list[str], tuple[str, ...], tuple[str, ...]]]:
    grouped: dict[tuple, list[str]] = {}
    for agent, policy in policies.items():
        rules = (tuple(policy.get("allow_patterns", ())),
                 tuple(policy.get("disallow_patterns", ())))
        if any(rules):
            grouped.setdefault(rules, []).append(agent)
    return [(agents, allow, disallow) for (allow, disallow), agents in grouped.items()]


def audit(args: argparse.Namespace) -> dict:
    parsed = urlsplit(args.url if "://" in args.url else f"https://{args.url}")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be an http:// or https:// URL")

    scheme = parsed.scheme
    hostname = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)
    normal_host = hostname if port in (80, 443) else f"{hostname}:{port}"
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    random_host = f"probe-{secrets.token_hex(6)}.invalid"

    baseline, _ = _request(
        connect_host=hostname, port=port, scheme=scheme, sni=hostname,
        host_header=normal_host, path=path, timeout=args.timeout, name="baseline",
    )
    probes = [baseline]
    cases = ([("random_host_and_sni", random_host, random_host)]
             if scheme == "https" else [("random_host", hostname, random_host)])
    for name, sni, host_header in cases:
        result, _ = _request(
            connect_host=hostname, port=port, scheme=scheme, sni=sni,
            host_header=host_header, path=path, timeout=args.timeout, name=name,
        )
        result.accepted_like_baseline = _looks_like_baseline(result, baseline)
        probes.append(result)

    robots_url = urlunsplit((scheme, parsed.netloc, "/robots.txt", "", ""))
    robots_result, robots_body, robots_chain = _fetch_robots(
        robots_url, args.timeout, args.max_redirects,
    )
    interpretation, policies = evaluate_robots_response(
        robots_result.status, robots_body.decode("utf-8", "replace"),
        args.agent, robots_result.error, args.path,
    )
    robots = {
        "status": robots_result.status,
        "error": robots_result.error,
        "url": robots_chain[-1]["url"] if robots_chain else robots_url,
        "fetch_chain": robots_chain,
        "interpretation": interpretation,
        "agents": policies,
    }
    bot_access = _bot_access_summary(policies)
    host_validation = _probe_validation_summary(
        probes, "random_host_and_sni" if scheme == "https" else "random_host"
    )
    return {
        "summary": {
            "bots_allowed": bot_access,
            "server_checks_hostname_sni": host_validation,
        },
        "target": args.url,
        "random_hostname": random_host,
        "robots": robots,
        "probes": [asdict(probe) for probe in probes],
    }


def _print_report(report: dict) -> None:
    summary = report["summary"]
    target = report["target"]
    scheme = urlsplit(target if "://" in target else f"https://{target}").scheme
    label = "hostname/SNI" if scheme == "https" else "hostname"
    print(f"Bots allowed to access? {summary['bots_allowed']}")
    print(f"Server checks {label}? {summary['server_checks_hostname_sni']}")
    print("\nConsequences")
    if summary["bots_allowed"] == "Yes":
        print("  AI data-collection bots are allowed and could be manipulated "
              "to send enough requests to DoS this site.")
    elif summary["bots_allowed"] == "Partially":
        print("  AI data-collection bots are allowed on some paths and could be "
              "manipulated to send enough requests to DoS this site.")
    if summary["server_checks_hostname_sni"] == "No":
        if scheme == "https":
            print("  The server accepts an unknown hostname/SNI pair. Even with "
                  "robots.txt, bots that ignore TLS certificate mismatches could be "
                  "manipulated to DoS this site.")
        else:
            print("  The server accepts an unknown hostname, allowing bots to "
                  "reach this site under another host name.")
    if (summary["bots_allowed"] == "No"
            and summary["server_checks_hostname_sni"] == "Yes"):
        print("  No AI-bot DoS exposure was indicated by these checks.")
    elif (summary["bots_allowed"] == "Unknown"
          or summary["server_checks_hostname_sni"] == "Unknown"):
        print("  The consequences could not be fully determined from these checks.")
    if summary["bots_allowed"] == "Partially":
        groups = _policy_rule_groups(report["robots"]["agents"])
        print("  Partial robots.txt rules:")
        if not groups:
            print("    Some checked bots or paths are allowed and others are blocked.")
        for agents, allow_patterns, disallow_patterns in groups:
            print(f"    {', '.join(agents)}")
            for pattern in disallow_patterns:
                print(f"      Disallow: {pattern}")
            for pattern in allow_patterns:
                print(f"      Allow: {pattern}")
    print("\nDetails")
    print(f"Target: {report['target']}")
    robots = report["robots"]
    print(f"robots.txt: url={robots['url']} status={robots['status']} "
          f"interpretation={robots['interpretation']} error={robots['error'] or 'none'}")
    for hop in robots["fetch_chain"]:
        if hop["location"]:
            print(f"  redirect {hop['status']}: {hop['url']} -> {hop['location']}")
    for agent, rules in robots["agents"].items():
        state = "allowed" if rules["root_allowed"] else "blocked"
        restrictions = "yes" if rules["declares_disallow"] else "no"
        print(f"  {agent:<18} / is {state}; declares disallow={restrictions}")
        for path, allowed in rules["paths"].items():
            if path not in ("/", "/robots.txt"):
                print(f"    {path}: {'allowed' if allowed else 'blocked'}")
    print("Virtual-host probes:")
    for probe in report["probes"]:
        accepted = probe["accepted_like_baseline"]
        comparison = "baseline" if accepted is None else str(accepted).lower()
        detail = probe["error"] or (
            f"status={probe['status']} type={probe['content_type'] or '-'} "
            f"bytes={probe['body_bytes']}"
        )
        print(f"  {probe['name']:<22} accepted_like_baseline={comparison:<8} {detail}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--agent", action="append", default=[],
                        help="Additional robots.txt user-agent token (repeatable)")
    parser.add_argument("--path", action="append", default=[],
                        help="Additional URL path to evaluate (repeatable)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="Timeout per request in seconds (default: 8)")
    parser.add_argument("--max-redirects", type=int, default=5,
                        help="Maximum robots.txt redirects to follow (default: 5)")
    parser.add_argument("--json", action="store_true", help="Print JSON")
    args = parser.parse_args(argv)
    if not 0.1 <= args.timeout <= 30:
        parser.error("--timeout must be between 0.1 and 30 seconds")
    if any(not path.startswith("/") for path in args.path):
        parser.error("every --path must begin with /")
    if not 0 <= args.max_redirects <= 10:
        parser.error("--max-redirects must be between 0 and 10")
    args.agent = list(dict.fromkeys([*DEFAULT_AGENTS, *args.agent]))
    return args


def main() -> None:
    try:
        args = parse_args()
        report = audit(args)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            _print_report(report)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
