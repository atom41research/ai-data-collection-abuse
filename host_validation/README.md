# Host, SNI, and robots.txt checker

Fetches `/robots.txt`, evaluates it for common AI crawler tokens, and sends
small comparison requests using:

1. the normal hostname in both TLS SNI and the HTTP `Host` header;
2. the same synthetic hostname in both fields.

For plain HTTP, which has no SNI, only the `Host` header changes.

TLS certificate verification is deliberately disabled for these probes: the
test asks whether the **server** rejects an unexpected hostname/SNI pair. The
tool does not follow redirects for Host/SNI comparison requests. It follows up
to five HTTP(S) redirects for `robots.txt`, reports the fetch chain, and reads
at most 1 MiB per response.

No installation is needed beyond Python 3.10+. From the repository root, the
basic `uv` command is:

```bash
uv run python host_validation/check.py https://app.example.test/
```

SNI is a TLS feature, so use an `https://` target to test it. Add crawler
tokens, paths, or machine-readable output:

```bash
uv run python host_validation/check.py https://app.example.test/ \
  --agent MyCrawler --path /private/ --path '/search?preview=1' \
  --max-redirects 5 --json
```

Interpret `accepted_like_baseline: true` as a signal to review virtual-host
configuration. It is not conclusive when responses are dynamic.

The robots evaluator reports:

- whether `/`, `/robots.txt`, and requested `--path` values are allowed;
- whether the best-matching agent group declares any `Disallow` rule;
- RFC 9309 availability handling for 2xx, 4xx, and 5xx responses;
- unresolved redirects and network failures as unknown rather than guessing.

## Tests

```bash
cd host_validation
uv run python -m unittest -v
```

The suite currently contains 35 tests covering bounded relative and
cross-host redirects, redirect loops, CLI regression checks, group selection
and merging,
case variations, BOM/CRLF/comments, empty and malformed files, `Allow` versus
`Disallow` precedence, wildcards, end anchors, percent encoding, Unicode and
case-sensitive paths, query strings, partial rules, HTTP status semantics,
response comparison, real local HTTP requests, and real TLS SNI
acceptance/rejection. It does not claim to predict non-standard vendor
behavior; the raw status and interpretation remain visible.
