# AI bot exposure research toolkit

Small, auditable tools supporting the research described in *Playing with AI
Data Collection Bots for Fun and Profit*. Each tool lives in its own folder and
has its own usage guide.

## Tool map

| Folder | Purpose | Network activity |
| --- | --- | --- |
| [`host_validation/`](host_validation/) | Check AI-crawler rules in `robots.txt` and compare normal requests with a matching synthetic `Host`/TLS SNI pair. | Two probes plus `robots.txt` fetches. |
| [`largest_resources/`](largest_resources/) | Breadth-first browser crawl that ranks observed resources by wire and decoded size. | Visits up to 25 same-host pages by default. |
| [`page_generator/`](page_generator/) | Generate a static proof-of-concept HTML page from a CLI or browser interface, with controlled test links and optional OOB detection markers. | None; it only creates local HTML. |

## Responsible use

Use these tools only on systems you own or have explicit permission to test.
The page generator is capped at 1,000 links and includes detection-only payloads, not
remote-code-execution payloads. Nothing here deploys pages, obtains
certificates, triggers third-party crawlers, changes DNS, or performs load
testing.

The checks are indicators, not proofs: dynamic pages, CDNs, reverse proxies,
and shared hosting can make `Host`/SNI comparisons ambiguous. Confirm findings
in the server configuration and logs.

## Install with uv

[`uv`](https://docs.astral.sh/uv/) creates the environment and installs the
only third-party dependency:

```bash
uv sync
uv run playwright install chromium
```

Chromium is needed only by `largest_resources`; skip the second command when
using only the host checker or page generator.

Run the tools from the repository root:

```bash
uv run python host_validation/check.py https://owned.example.test/
uv run python largest_resources/find_largest.py https://owned.example.test/
uv run python page_generator/generate.py https://owned.example.test/resource
```

## Install with venv/pip

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r largest_resources/requirements.txt
playwright install chromium
```

The host checker and page generator use only the Python standard library and
can be run without installing Playwright.

## Requirements

- Python 3.10+ (`python3` in the examples below)
- Playwright and Chromium only for `largest_resources`

Each folder's README contains exact commands.

## GitHub Pages

The repository-root [`index.html`](index.html) is the page-generator
interface. After pushing the repository, select **Settings → Pages → Deploy
from a branch → `main` → `/ (root)`**. The project page will be available at:

```text
https://USERNAME.github.io/REPOSITORY/
```
