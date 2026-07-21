# Proof-of-concept page generator

Creates a static HTML page containing links to one or more authorized target
URLs. It does not send requests, publish the page, change DNS, obtain a
certificate, or contact a crawler.

It uses only the Python standard library. No installation is required; prefix
CLI examples with `uv run` when using the repository's uv environment.

The built-in payloads are detection-only:

- `marker`: a unique query value;
- `cache-bust`: a unique value useful for checking cache-key behavior at low volume;
- `blind-xss`: a basic event-handler injection that runs only a one-shot HTTP callback;
- `log4j-dns`: a DNS-only JNDI callback marker (no codebase or class loading).

Generate incrementing labels:

```bash
uv run python page_generator/generate.py https://owned.example.test/resource \
  --count 25 --text-mode increment --text 'item {n}' \
  --output poc.html
```

Cycle through labels from the command line or choose random labels:

```bash
uv run python page_generator/generate.py https://owned.example.test/a https://owned.example.test/b \
  --count 20 --text red --text blue --text-mode cycle \
  --output poc.html

uv run python page_generator/generate.py --targets-file targets.txt --count 20 \
  --text-mode random --seed demo --output poc.html
```

Use an OOB detection marker on a lab target and callback service you control:

```bash
uv run python page_generator/generate.py https://lab.example.test/search \
  --count 10 --payload blind-xss --callback callback.example.test \
  --payload-param q --output poc.html
```

Or generate a DNS-only Log4j probe:

```bash
uv run python page_generator/generate.py https://lab.example.test/inspect \
  --payload log4j-dns --callback dns.callback.example.test \
  --payload-param value --output poc.html
```

Both presets require a callback host you control. The blind-XSS probe executes
only a `fetch` beacon; the Log4j probe does not request a remote class or run a
command.

Custom payload templates may use `{n}`, `{target}`, `{token}`, and `{callback}`:

```bash
uv run python page_generator/generate.py https://lab.example.test/inspect \
  --payload custom --payload-template 'research-marker-{n}' \
  --count 5 --output poc.html
```

The hard limit is 1,000 links. Use normal load-testing tools with explicit
rate controls for larger authorized capacity tests.

## Browser interface

Open [`../index.html`](../index.html) directly, or serve the repository locally:

```bash
uv run python -m http.server 8000
```

Then visit <http://127.0.0.1:8000/>. Generation and download happen
entirely in the browser; the interface does not request the entered targets.
