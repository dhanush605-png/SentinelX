# SentinelX – Web Attack Surface & Reconnaissance Tool

SentinelX is a modular Python 3.11+ reconnaissance toolkit for **authorized security testing**. It begins with reliable URL crawling, redirect-aware HTTP status collection and broken-link identification, then provides building blocks for endpoint discovery, passive subdomain discovery, JavaScript API extraction, security-header analysis and professional reporting.

## Safety boundary
Use only against systems you own or have explicit permission to assess. SentinelX does **not** perform exploitation, credential attacks, brute force, destructive actions, or vulnerability weaponization. Login automation (below) fills and submits a form **once**, with a single credential pair you already hold for your own target -- it is a convenience for reaching authenticated functionality, not a credential-guessing mechanism.

## Features
- Depth-limited web crawler with same-origin/site scope
- Optional JavaScript rendering (`--render-js`, headless Chromium via Playwright) for single-page apps, so client-side-routed links and JS-inserted scripts are discovered, not just server-rendered HTML
- Authenticated scanning: custom headers/API keys, a raw session cookie, HTTP Basic auth, a reusable Playwright storage-state session, or a one-shot login-form automation
- Redirect following and HTTP status collection
- Broken-link candidates: non-2xx/3xx responses and request errors
- Interesting paths: robots.txt, sitemap.xml, Swagger/OpenAPI
- Passive CT-based subdomain discovery (no DNS brute forcing)
- Parameter discovery: passive enumeration of every query-string, HTML-form and JavaScript-referenced parameter, plus optional active probing for hidden/unlinked parameter names (`--discover-params`) with differential response analysis, binary-split attribution, GET/POST-form/POST-JSON injection, and per-finding confidence scoring
- JavaScript endpoint extraction beyond quoted literals: recovers template-literal paths (`` `${base}/api/users/${id}` `` → `{}/api/users/{}`), path fragments left by string concatenation, and endpoints/sources mined from `sourceMappingURL` source maps
- Security-header, cookie, CORS and basic disclosure analysis
- JSON/CSV/HTML reporting
- CLI controls for depth, concurrency, timeout, rate limit, scope, proxy and output
- Tests, type hints, logging, Docker-ready architecture

## Install
```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
playwright install chromium   # only needed if you'll use --render-js
```

## Usage
```bash
python main.py https://example.com --depth 2 --timeout 10 --rate-limit 0.2 --scope same-origin --output reports --format all
python -m pytest -q
```

### JavaScript-rendered (SPA) targets
```bash
python main.py https://app.example.com --render-js
```
`--render-js` fetches every page with headless Chromium instead of a plain GET, waits for the page's own JavaScript to settle, and reads the *rendered* DOM -- so links added by a client-side router and scripts inserted after load are found the way a real browser (and a real attacker) would see them. Without it, an SPA that ships an near-empty HTML shell will look like a one-page site.

### Rendering performance
`--render-js` crawls are tuned to be fast by default. SentinelX only reads the rendered DOM, headers and cookies, so it skips what it never uses:

| Default | What it does | Opt out |
|---|---|---|
| Asset blocking | Aborts image / media / font requests | `--render-assets` |
| Stylesheet blocking | Aborts CSS requests | `--render-css` |
| Tracker blocking | Aborts known analytics hosts (Google Analytics, Hotjar, Sentry, ...) | `--allow-trackers` |
| Engine flags | `--disable-gpu`, `--disable-dev-shm-usage`, `--disable-background-timer-throttling` | -- |
| Context reuse | One browser + one context for the whole crawl (already the case) | -- |
| Targeted waits | `domcontentloaded`, then a bounded (max 5s) network-idle settle | -- |

Scripts, XHR/fetch, documents and WebSockets are **never** blocked, so SPA rendering and API discovery are unaffected.

Two things are deliberately opt-in rather than default:
- `--neutralize-canvas` stubs WebGL to save CPU, but it changes what the page renders; a recon tool usually wants to see what a real browser sees.
- `--browser-arg --no-sandbox` (repeatable) is needed in some containers, but it weakens Chromium's sandbox, so it is never applied silently. In Docker/CI, if Chromium fails with "No usable sandbox", add it explicitly.

### Authenticated scanning
Most of an application's interesting attack surface sits behind a login. SentinelX supports several ways to carry authentication, from simplest to most involved:
```bash
# A bearer token or API key
python main.py https://api.example.com --header "Authorization: Bearer <token>"

# A session cookie copied from your browser's DevTools
python main.py https://app.example.com --cookie "session=abc123; csrftoken=xyz"

# HTTP Basic auth
python main.py https://staging.example.com --basic-auth alice:hunter2

# Reuse a session you already logged into manually and exported
# (playwright's page.context.storage_state(path="state.json"))
python main.py https://app.example.com --render-js --auth-storage-state state.json

# Or have SentinelX log in once for you, then save the session for reuse
python main.py https://app.example.com --render-js \
  --login-url https://app.example.com/login --login-user alice --login-pass-env APP_PASSWORD \
  --save-storage-state state.json
```
`--header`/`--cookie`/`--basic-auth` apply to every request the crawl makes, with or without `--render-js`. `--auth-storage-state`, `--save-storage-state`, and `--login-*` all require `--render-js`, since they operate through the browser session; whatever authenticates the browser is copied into the same session used for JS-file fetches, endpoint probes, and CORS probing, so the whole run has one consistent authenticated identity. Prefer `--login-pass-env` (an environment variable name) over `--login-pass` so the password never lands in shell history or a process listing.

### Parameter discovery
Query-string and form parameters are always enumerated passively from the crawl -- including the fields of every HTML `<form>`, which a link-only crawl never inspected. Add active discovery of hidden parameter names the server accepts but never links:
```bash
# Probe a small built-in candidate list against crawled endpoints
python main.py https://app.example.com --discover-params

# Or supply your own candidate names (one per line, # comments allowed)
python main.py https://app.example.com --discover-params --param-wordlist params.txt
```
```bash
# Probe query, POST form body, and JSON body
python main.py https://app.example.com --discover-params --param-methods get,post,json
```
Active probing sends each candidate as a **benign unique marker value** (never an attack payload) and reports which parameters the endpoint acknowledges -- the same mapping technique as Arjun/ParamMiner. It is off by default and bounded by `--param-probe-max-endpoints` (default 10). How it decides:

- **Differential response analysis** -- a two-sample baseline measures how much the response naturally varies (status, byte length, word/line counts); a candidate only counts when it moves the response *beyond* that jitter, so dynamic pages don't produce false positives.
- **Binary-split attribution** -- a reflected marker maps straight to its name; a non-reflected group effect is isolated by recursively halving the batch, so a real-but-silent parameter is pinned to one name instead of an anonymous "something in this batch".
- **Injection locations** (`--param-methods`) -- `get` (query string), `post` (form body), `json` (JSON body).
- **Confidence scoring** -- each finding carries the evidence that produced it (reflection, status change, body-size change) and a high/medium/low confidence; reflection and status change are strong, a body-only change on an unstable baseline is weak.
- **JavaScript integration** -- parameter names read or appended in JavaScript (`searchParams.get('ref')`, `fd.append('user_id', …)`, query keys in URL literals) are harvested and added to the candidate list, and also surface passively (marked `js`) even without probing.

### JavaScript analysis beyond literals
Endpoint extraction no longer only sees fully-quoted string literals. For every script it also recovers template-literal paths (with `${...}` shown as `{}`), path fragments left behind by string concatenation, and -- when a bundle advertises a `sourceMappingURL` -- the readable endpoints and original source paths embedded in the `.map` file. Concrete URLs feed API Discovery/CORS as before; template shapes and non-API paths are reported as leads in the *Dynamic & Hidden Endpoints* section rather than fetched.

## Architecture
`crawler/spider.py` fetches and traverses pages (capturing headers, cookies, and script tags in the same pass), either with `requests` or, when `--render-js` is set, through `crawler/browser.py`'s headless-Chromium session; `crawler/auth.py` parses the authentication CLI flags; `discovery/` extracts passive attack-surface data; `analysis/security.py` evaluates defensive signals (headers, cookies, CORS); `main.py:build_report()` runs every module and buckets the results into one report section per feature; `reporting/` renders those sections; `tests/` protects core behavior (one test module per source module, plus `test_main_build_report.py` covering the end-to-end categorization and `tests/test_browser.py`/`tests/test_spider_render_js.py` covering the headless-browser path against a faked Playwright).

## Report structure
Every run produces one report with a section per feature -- Crawling, Broken Links, Redirects, Endpoint Discovery, JavaScript Analysis, JavaScript Analysis -- Dynamic & Hidden Endpoints, Parameter Discovery, API Discovery, Security Header Analysis, Cookie Analysis, CORS Analysis, and Passive Subdomain Discovery. A feature that finds nothing still gets a section, with an explicit "No findings for <feature>" message (or a specific reason, e.g. Passive Subdomain Discovery explains when a target has no public DNS/TLS presence to query) -- so the report always shows full feature coverage, not just a list of problems.
- `report.html` -- one browsable page, sidebar nav with a per-feature finding count.
- `report.json` -- the same structure as data, `{"target", "pages_crawled", "sections": [...]}`.
- `csv/<feature>.csv` -- one CSV per feature, plus `csv/_summary.csv` (feature, count, status).

A hidden endpoint referenced only in JavaScript (not linked from any crawled page) is still fetched live for API Discovery and probed for CORS -- "not linked" isn't treated as "not reachable".

## Packaging a release
Don't zip the working tree directly -- `.gitignore` doesn't apply to a manual archive command, so `__pycache__/`, `.pytest_cache/`, and `*.pyc` will sneak in. Use:
```bash
./scripts/package.sh SentinelX.zip
```

## Recommended lab
Use **OWASP Juice Shop** or **DVWA** locally/containerized. Point SentinelX only at the local lab URL. Capture screenshots of the CLI, discovered URLs, status-code table, and HTML report for your portfolio. Do not scan public targets without written authorization.

## Roadmap
1. Add asynchronous crawler with bounded concurrency and a token-bucket rate limiter.
2. Add form/input parameter extraction and normalized endpoint inventory.
3. Add JS asset crawling and source-map-aware endpoint extraction.
4. Add robots/sitemap/OpenAPI parsers and evidence-based findings.
5. Add configurable disclosure rules and CORS/cookie checks.
6. Add report severity/evidence sections and scan metadata.
7. Add Dockerfile, CI, coverage, and integration tests against a local lab.

## Resume value
A strong portfolio version should demonstrate engineering quality—not just scanning: scope enforcement, rate limiting, deterministic evidence, modular plugins, tests, CI, Docker, and polished reports. Example resume bullet: “Built SentinelX, a modular Python web attack-surface reconnaissance tool with scoped crawling, redirect/status analysis, passive subdomain discovery, JavaScript API extraction, security-header/CORS/cookie checks, and HTML/JSON/CSV reporting for authorized lab environments.”


### Fragment-aware parameter discovery

SentinelX also inventories client-side parameters embedded in URL fragments,
including SPA routes such as `/#/search?q=admin`. These are reported separately
as `fragment` parameters with method `CLIENT`, because URL fragments are not
sent to the HTTP server. This complements normal query, form, and JavaScript
parameter discovery and requires no additional requests.

Fragment parameters are no longer only recovered from `<a href>` links: a hash
route or hash query string written directly into a script as a string or
template literal (a router table entry, `location.hash = '#tab=info'`,
`navigate('#/search?q=admin')`, `` `#/search?q=${term}` ``) is now parsed by
the same JavaScript analysis pass that already extracts other parameter names,
so fragment parameters that exist only in JS source -- never rendered into a
link -- are still found. Route-only hashes, bare anchors, and non-parameter
strings that happen to start with `#` (e.g. a CSS hex color) are filtered out
automatically, since only a fragment that is actually query-like ever produces
a parameter.
