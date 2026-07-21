# Proof-of-concept page generator

Creates a static HTML page containing links to one or more authorized target
URLs. It does not send requests, publish the page, change DNS, obtain a
certificate, or contact a crawler.

It uses only the Python standard library. No installation is required; prefix
CLI examples with `uv run` when using the repository's uv environment.

The built-in payloads are detection-only:

- `marker`: unique traceable request values;
- `cache-bust`: unique cache-busting values;
- `blind-xss`: 12 curated combinations of breakout contexts and one-shot
  callback execution methods;
- `log4j-dns`: 10 curated DNS-only JNDI lookup variants (no codebase or class loading).

DoS/DoW vectors support up to 1,000 unique values. OOB vectors default to and
cap the page size at their curated catalog size. Lower `--count` when a smaller
authorized test is enough.

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

Both presets require a callback hostname or URL you control. A bare hostname
uses HTTPS for the blind-XSS beacon; the Log4j probe uses only the hostname.
The blind-XSS probe executes only an image beacon, and the Log4j probe does not
request a remote class or run a command.

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
The interface groups templates into DoS/Denial-of-Wallet and OOB attack
vectors, with uncommon controls under **Advanced options**.
