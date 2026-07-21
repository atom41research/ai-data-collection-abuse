# Largest-resource finder

A small breadth-first Playwright crawler derived from:

`/home/n8e/CursorProjects/bd/bot-research/crawler/`

It visits same-host HTML pages and records every browser response, including
scripts, stylesheets, fonts, images, documents, and cross-host subresources.
Results are ranked by both Chromium's encoded transfer size and decoded body
size. The default crawl is intentionally small: 25 pages, one browser page at
a time, and at most 64 MiB read into memory for any one decoded body.

## Install

From the repository root with `uv`:

```bash
uv sync
uv run playwright install chromium
```

Or with standard `venv`/pip from this directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
playwright install chromium
```

## Run

```bash
uv run python largest_resources/find_largest.py https://owned.example.test/
```

Useful options:

```bash
uv run python largest_resources/find_largest.py https://owned.example.test/ \
  --max-pages 50 --top 30 --output crawl-results/result.json
```

Use `--skip-bodies` when wire size and `Content-Length` are enough and you do
not want the tool to retain decoded bodies for measurement. The crawler does
not attempt cache bypasses or mutate discovered URLs.
