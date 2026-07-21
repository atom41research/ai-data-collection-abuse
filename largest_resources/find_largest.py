#!/usr/bin/env python3
"""Find large resources on a target site with a bounded BFS crawl."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


@dataclass
class Resource:
    url: str
    page_url: str
    status: int
    content_type: str
    content_length: int
    decoded_bytes: int
    wire_bytes: int
    same_host: bool


def normalize_url(url: str) -> str | None:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    port = parsed.port
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)))
    return urlunsplit((parsed.scheme.lower(), netloc, path, query, ""))


def _bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return str(value)


async def crawl(args: argparse.Namespace) -> dict:
    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError("Playwright is not installed; see largest_resources/README.md") from exc

    seed = normalize_url(args.url)
    if seed is None:
        raise ValueError("target must be an absolute HTTP(S) URL")
    target_host = urlsplit(seed).hostname or ""
    queue = deque([seed])
    seen = {seed}
    visited: list[str] = []
    resources: dict[str, Resource] = {}
    started = time.monotonic()

    async with async_playwright() as playwright:
        try:
            browser = await playwright.chromium.launch(headless=not args.headful)
        except Exception as exc:
            raise RuntimeError(
                "Chromium could not start; run `playwright install chromium`"
            ) from exc
        context = await browser.new_context()
        try:
            while queue and len(visited) < args.max_pages:
                page_url = queue.popleft()
                print(f"[{len(visited) + 1}/{args.max_pages}] {page_url}", file=sys.stderr)
                page = await context.new_page()
                cdp = await context.new_cdp_session(page)
                await cdp.send("Network.enable")
                request_urls: dict[str, str] = {}
                wire_sizes: dict[str, int] = {}
                responses = []

                def request_sent(event: dict) -> None:
                    request_urls[event.get("requestId", "")] = (
                        event.get("request", {}).get("url", "")
                    )

                def loading_finished(event: dict) -> None:
                    url = request_urls.get(event.get("requestId", ""), "")
                    if url:
                        wire_sizes[url] = max(
                            wire_sizes.get(url, 0), int(event.get("encodedDataLength", 0))
                        )

                cdp.on("Network.requestWillBeSent", request_sent)
                cdp.on("Network.loadingFinished", loading_finished)
                page.on("response", responses.append)
                deadline = time.monotonic() + args.timeout

                try:
                    await page.goto(
                        page_url, wait_until="domcontentloaded",
                        timeout=int(args.timeout * 1000),
                    )
                    if not visited:
                        final_host = urlsplit(page.url).hostname
                        if final_host:
                            target_host = final_host.lower()
                    remaining_ms = max(0, int((deadline - time.monotonic()) * 1000))
                    if remaining_ms:
                        try:
                            await page.wait_for_load_state("networkidle", timeout=min(2000, remaining_ms))
                        except Exception:
                            pass
                except Exception as exc:
                    print(f"  navigation: {type(exc).__name__}: {exc}", file=sys.stderr)

                for response in responses:
                    headers = response.headers
                    try:
                        content_length = int(headers.get("content-length", 0))
                    except ValueError:
                        content_length = 0
                    decoded = 0
                    may_read = (
                        not args.skip_bodies
                        and (not content_length or content_length <= args.max_body_mb * 1024 * 1024)
                        and time.monotonic() < deadline
                    )
                    if may_read:
                        try:
                            remaining = max(0.1, deadline - time.monotonic())
                            decoded = len(await asyncio.wait_for(response.body(), timeout=remaining))
                        except Exception:
                            pass
                    host = (urlsplit(response.url).hostname or "").lower()
                    record = Resource(
                        url=response.url,
                        page_url=page_url,
                        status=response.status,
                        content_type=headers.get("content-type", "unknown").split(";", 1)[0],
                        content_length=content_length,
                        decoded_bytes=decoded,
                        wire_bytes=wire_sizes.get(response.url, 0),
                        same_host=host == target_host,
                    )
                    previous = resources.get(record.url)
                    if previous is None or (record.wire_bytes, record.decoded_bytes) > (
                        previous.wire_bytes, previous.decoded_bytes
                    ):
                        resources[record.url] = record

                if time.monotonic() < deadline:
                    try:
                        links = await page.eval_on_selector_all(
                            "a[href]", "els => els.map(el => el.href)"
                        )
                        for link in links:
                            normalized = normalize_url(urljoin(page.url, link))
                            if (normalized and normalized not in seen
                                    and urlsplit(normalized).hostname == target_host):
                                seen.add(normalized)
                                queue.append(normalized)
                    except Exception:
                        pass
                visited.append(page_url)
                try:
                    await cdp.detach()
                except Exception:
                    pass
                await page.close()
        finally:
            await context.close()
            await browser.close()

    records = list(resources.values())
    return {
        "seed_url": seed,
        "effective_host": target_host,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.monotonic() - started, 2),
        "pages_visited": visited,
        "urls_discovered": len(seen),
        "resources": [asdict(record) for record in records],
    }


def _print_top(report: dict, field: str, label: str, top: int) -> None:
    records = sorted(report["resources"], key=lambda item: item[field], reverse=True)[:top]
    print(f"\nTop {len(records)} resources by {label}:")
    print(f"  {'size':>11}  {'scope':<5}  {'status':>6}  {'type':<25}  URL")
    for record in records:
        scope = "same" if record["same_host"] else "cross"
        print(f"  {_bytes(record[field]):>11}  {scope:<5}  {record['status']:>6}  "
              f"{record['content_type'][:25]:<25}  {record['url']}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Seed URL")
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--timeout", type=float, default=15,
                        help="Maximum seconds per page (default: 15)")
    parser.add_argument("--max-body-mb", type=int, default=64,
                        help="Largest decoded body retained in memory (default: 64)")
    parser.add_argument("--skip-bodies", action="store_true")
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--output", type=Path,
                        help="JSON output path (default: crawl-results/<host>-<time>.json)")
    args = parser.parse_args(argv)
    if not 1 <= args.max_pages <= 100:
        parser.error("--max-pages must be between 1 and 100")
    if not 1 <= args.timeout <= 30:
        parser.error("--timeout must be between 1 and 30 seconds")
    if not 1 <= args.max_body_mb <= 64:
        parser.error("--max-body-mb must be between 1 and 64")
    if not 1 <= args.top <= 100:
        parser.error("--top must be between 1 and 100")
    return args


def main() -> None:
    try:
        args = parse_args()
        report = asyncio.run(crawl(args))
        if args.output is None:
            host = report["effective_host"] or "unknown"
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            args.output = Path("crawl-results") / f"{host}-{stamp}.json"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"\nVisited {len(report['pages_visited'])} pages; "
              f"observed {len(report['resources'])} unique resources.")
        _print_top(report, "wire_bytes", "wire size", args.top)
        _print_top(report, "decoded_bytes", "decoded size", args.top)
        print(f"\nJSON: {args.output}")
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
