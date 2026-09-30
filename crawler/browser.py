from __future__ import annotations

"""Headless-browser page fetching for JavaScript-rendered (SPA) targets.

Plain `requests` + BeautifulSoup only ever sees a page's server-rendered
HTML. A modern single-page app often ships an almost-empty HTML shell and
builds the real DOM -- including the links and API calls SentinelX cares
about -- with JavaScript after load, so a request-only crawl silently
misses most of its attack surface. `BrowserSession` drives real headless
Chromium via Playwright, lets the page's own JavaScript run, and hands back
the *rendered* DOM so the rest of the crawler (crawler.spider.Crawler) can
run the exact same link/script extraction it already uses for
server-rendered HTML.

This module also carries authentication across the render boundary: a
pre-authenticated Playwright `storage_state` (cookies + localStorage
exported from a real logged-in session) can be loaded up front, or a
one-shot login form fill+submit can be run once before crawling starts.
Either way, the resulting session cookies are copied back into SentinelX's
`requests.Session` so every other HTTP call the tool makes (JS-file
fetches, endpoint probes, CORS probing) rides the same authenticated
session as the browser-driven crawl -- there is exactly one authenticated
identity per run, not two that can drift apart.

Nothing here guesses or brute-forces credentials: `login()` fills a form
with the single username/password the tester already possesses for their
own authorized target and submits it once, the same way a human tester
would sign in before starting a manual assessment.

Performance notes
------------------
A few things are done here specifically because a recon crawl renders
many pages back-to-back rather than one page a human is looking at:

- Static assets (images, media, fonts, and -- unless the caller opts out --
  stylesheets) and known analytics/tracker hosts are aborted at the network
  layer via `BrowserContext.route()`. None of them affect the things
  SentinelX actually reads off the page (the link/script DOM, JS-endpoint
  extraction, headers, cookies), so skipping their download cuts per-page
  bandwidth and latency for free. Scripts, documents, XHR/fetch, and
  WebSocket traffic are never blocked -- those are exactly what makes an
  SPA's real DOM and API surface show up in the first place.
- One `Browser` + one `BrowserContext` is reused for every page in the
  crawl (new_page() per URL, not new_context()/new browser), so session
  cookies/localStorage persist across navigations and no crawl pays
  Chromium's process-launch cost more than once.
- Chromium is launched with a small set of flags that remove rendering
  work headless crawling never needed (GPU compositing, background timer
  throttling, /dev/shm pressure in containers) -- see `DEFAULT_ENGINE_ARGS`.
  `--no-sandbox` is deliberately *not* one of the defaults: it measurably
  weakens Chromium's process sandbox, which matters here because every
  page navigated to is attacker-relevant (the recon target itself, or
  whatever it links to). Pass it explicitly via `extra_launch_args` if a
  container environment truly requires it (e.g. no usable user namespace).
- Canvas/WebGL is left alone by default. A generic scraper can safely stub
  it out to avoid background render-loop CPU cost, but a recon tool that's
  trying to see a page the way a real browser (and a real attacker) would
  is exactly the case where silently changing what the page renders --
  and what any canvas-fingerprint-gated bot check sees -- is the wrong
  trade. Set `neutralize_canvas=True` to opt into the CPU savings when
  that accuracy doesn't matter for a given target.
"""

from dataclasses import dataclass, field

# Resource types that never affect link/script extraction, JS-endpoint
# discovery, headers, or cookies -- safe to abort unconditionally.
BLOCKED_RESOURCE_TYPES = frozenset({'image', 'media', 'font'})
# Blocked separately (not unconditionally) since a future feature could
# need computed styles/visibility; on by default, opt-out via
# BrowserSession(block_stylesheets=False).
STYLESHEET_RESOURCE_TYPE = 'stylesheet'

# Common third-party analytics/tracking hosts: aborting these avoids
# spending navigation-timeout budget on beacons that never touch the
# page's own DOM, and avoids the crawl showing up in a target's analytics.
BLOCKED_TRACKER_PATTERNS = (
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'connect.facebook.net', 'facebook.com/tr', 'hotjar.com', 'sentry.io',
    'segment.io', 'segment.com', 'mixpanel.com', 'clarity.ms',
)

# Removes rendering/scheduling work a headless, off-screen crawl never
# benefits from. Intentionally excludes --no-sandbox -- see module
# docstring "Performance notes".
DEFAULT_ENGINE_ARGS = (
    '--disable-gpu',
    '--disable-dev-shm-usage',
    '--disable-background-timer-throttling',
)

@dataclass
class BrowserFetchResult:
    status: int | None
    final_url: str
    content_type: str
    headers: dict
    html: str
    set_cookie_headers: list = field(default_factory=list)
    error: str | None = None


_CANVAS_INIT_SCRIPT = """
HTMLCanvasElement.prototype.getContext = new Proxy(
  HTMLCanvasElement.prototype.getContext,
  { apply(target, thisArg, args) {
      const type = args[0];
      if (type && String(type).toLowerCase().includes('webgl')) return null;
      return Reflect.apply(target, thisArg, args);
  } }
);
"""


def _require_playwright():
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError as e:
        raise RuntimeError(
            "--render-js requires Playwright, which isn't installed. Install it with:\n"
            "  pip install playwright\n"
            "  playwright install chromium\n"
            "then re-run SentinelX."
        ) from e


class BrowserSession:
    """One headless-Chromium browser context, reused across every page in a
    crawl -- session cookies and localStorage persist between navigations
    exactly like tabs in a real logged-in browser."""

    DEFAULT_USER_AGENT = 'SentinelX/1.0 (authorized-security-testing)'

    def __init__(self, proxy=None, extra_headers=None, seed_cookies=None, storage_state=None, *,
                 block_resources: bool = True, block_stylesheets: bool = True,
                 block_trackers: bool = True, neutralize_canvas: bool = False,
                 extra_launch_args: list[str] | None = None):
        """
        block_resources: abort image/media/font requests (never needed for
            link/script extraction, JS-endpoint discovery, headers, or
            cookies). On by default; set False to see a byte-for-byte
            faithful render (e.g. investigating an image/media-serving bug).
        block_stylesheets: also abort stylesheet requests. On by default
            since SentinelX never computes layout/visibility; kept as a
            separate flag from block_resources so it can be turned off on
            its own if a future check needs computed styles.
        block_trackers: abort known analytics/tracker hosts regardless of
            resource type (they're usually script/xhr, so block_resources
            doesn't catch them).
        neutralize_canvas: stub out WebGL contexts to avoid background
            render-loop CPU cost. Off by default -- see module docstring;
            a recon tool generally wants to see what a real browser renders.
        extra_launch_args: additional Chromium flags appended after
            DEFAULT_ENGINE_ARGS, e.g. ['--no-sandbox'] for a container
            without a usable sandbox/user namespace.
        """
        _require_playwright()
        self._proxy = proxy
        self._extra_headers = dict(extra_headers or {})
        self._seed_cookies = list(seed_cookies or [])
        self._storage_state = storage_state
        self._block_resources = block_resources
        self._block_stylesheets = block_stylesheets
        self._block_trackers = block_trackers
        self._neutralize_canvas = neutralize_canvas
        self._extra_launch_args = list(extra_launch_args or [])
        self._playwright_cm = None
        self._playwright = None
        self._browser = None
        self._context = None

    def _resource_interceptor(self, route) -> None:
        request = route.request
        blocked_types = BLOCKED_RESOURCE_TYPES | (
            {STYLESHEET_RESOURCE_TYPE} if self._block_stylesheets else set()
        )
        if self._block_resources and request.resource_type in blocked_types:
            route.abort()
            return
        if self._block_trackers and any(p in request.url.lower() for p in BLOCKED_TRACKER_PATTERNS):
            route.abort()
            return
        route.continue_()

    def __enter__(self):
        from playwright.sync_api import sync_playwright
        self._playwright_cm = sync_playwright()
        self._playwright = self._playwright_cm.__enter__()
        launch_kwargs = {'args': list(DEFAULT_ENGINE_ARGS) + self._extra_launch_args}
        if self._proxy:
            launch_kwargs['proxy'] = {'server': self._proxy}
        self._browser = self._playwright.chromium.launch(headless=True, **launch_kwargs)
        context_kwargs = {'user_agent': self._extra_headers.get('User-Agent', self.DEFAULT_USER_AGENT)}
        if self._storage_state:
            context_kwargs['storage_state'] = self._storage_state
        self._context = self._browser.new_context(**context_kwargs)
        non_ua_headers = {k: v for k, v in self._extra_headers.items() if k.lower() != 'user-agent'}
        if non_ua_headers:
            self._context.set_extra_http_headers(non_ua_headers)
        pw_cookies = self._to_playwright_cookies(self._seed_cookies)
        if pw_cookies:
            self._context.add_cookies(pw_cookies)
        if self._block_resources or self._block_trackers:
            self._context.route('**/*', self._resource_interceptor)
        if self._neutralize_canvas:
            self._context.add_init_script(_CANVAS_INIT_SCRIPT)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._context is not None:
                self._context.close()
            if self._browser is not None:
                self._browser.close()
        finally:
            if self._playwright_cm is not None:
                self._playwright_cm.__exit__(exc_type, exc, tb)

    @staticmethod
    def _to_playwright_cookies(cookies) -> list[dict]:
        """`cookies` is an iterable of requests.cookies.Cookie objects (as
        found by iterating a requests.cookiejar.CookieJar). Playwright
        requires a domain on every cookie it's given."""
        out = []
        for c in cookies:
            domain = getattr(c, 'domain', '') or ''
            if not domain:
                continue
            out.append({
                'name': c.name,
                'value': c.value,
                'domain': domain,
                'path': getattr(c, 'path', '/') or '/',
            })
        return out

    def login(self, login_url, user, password, *,
              user_selector='input[name="username"], input[name="email"], input[type="email"]',
              pass_selector='input[name="password"], input[type="password"]',
              submit_selector='button[type="submit"], input[type="submit"]',
              wait_selector=None, timeout=15.0):
        """Fill and submit a login form exactly once. This automates a
        single legitimate sign-in with tester-supplied credentials -- it is
        not a brute-force or credential-guessing mechanism."""
        timeout_ms = timeout * 1000
        page = self._context.new_page()
        try:
            page.goto(login_url, wait_until='domcontentloaded', timeout=timeout_ms)
            page.fill(user_selector, user, timeout=timeout_ms)
            page.fill(pass_selector, password, timeout=timeout_ms)
            page.click(submit_selector, timeout=timeout_ms)
            if wait_selector:
                page.wait_for_selector(wait_selector, timeout=timeout_ms)
            else:
                self._settle(page, timeout_ms)
        finally:
            page.close()

    def sync_cookies_into(self, requests_session) -> None:
        """Copy the browser context's current cookie jar into a
        requests.Session, so plain-HTTP calls made outside the browser
        (JS-file fetches, endpoint probes, CORS probing) see the same
        authenticated session as the rendered crawl."""
        for c in self._context.cookies():
            requests_session.cookies.set(
                c['name'], c['value'],
                domain=c.get('domain') or '', path=c.get('path') or '/',
            )

    def save_storage_state(self, path: str) -> None:
        self._context.storage_state(path=path)

    def get(self, url: str, timeout: float = 10.0) -> BrowserFetchResult:
        timeout_ms = timeout * 1000
        page = self._context.new_page()
        try:
            response = page.goto(url, wait_until='domcontentloaded', timeout=timeout_ms)
            if response is None:
                return BrowserFetchResult(None, url, '', {}, '',
                                           error='no response (navigation blocked, or a same-page anchor)')
            self._settle(page, timeout_ms)
            html = page.content()
            headers = {k.lower(): v for k, v in response.headers.items()}
            return BrowserFetchResult(
                status=response.status,
                final_url=page.url,
                content_type=headers.get('content-type', ''),
                headers=headers,
                html=html,
                set_cookie_headers=self._cookie_lines_for(page.url),
            )
        except Exception as e:  # Playwright's own TimeoutError and friends
            return BrowserFetchResult(None, url, '', {}, '', error=str(e))
        finally:
            page.close()

    @staticmethod
    def _settle(page, timeout_ms):
        """Give SPA JavaScript a chance to finish rendering after the
        initial DOM loads, without hanging forever on a page that keeps a
        connection open (websockets, polling). Best-effort: a timeout here
        just means we read the DOM a little earlier, not a failed fetch."""
        try:
            page.wait_for_load_state('networkidle', timeout=min(timeout_ms, 5000))
        except Exception:
            pass

    def _cookie_lines_for(self, url: str) -> list[str]:
        """Rebuild Set-Cookie-shaped strings from the context's structured
        cookie jar (name/value/secure/httpOnly/sameSite) so the existing
        analysis.security.parse_cookies() can flag issues exactly as it does
        for a requests-based crawl. Playwright/CDP doesn't reliably expose a
        raw, per-cookie Set-Cookie response header, but it does expose fully
        parsed cookie objects -- which is what we want anyway.

        Every currently-set cookie for `url` is reported on each page that
        loads it, not just the response that first set it; main.py already
        deduplicates cookie findings by name, so this only affects which
        page is shown as "Set On" (the first page in crawl order, in
        practice usually the target's homepage) -- a minor, documented
        simplification, not a correctness issue for the flags being
        reported.
        """
        lines = []
        for c in self._context.cookies(url):
            parts = [f"{c['name']}={c['value']}"]
            if c.get('secure'):
                parts.append('Secure')
            if c.get('httpOnly'):
                parts.append('HttpOnly')
            same_site = c.get('sameSite')
            if same_site and same_site != 'None':
                parts.append(f'SameSite={same_site}')
            elif same_site == 'None':
                parts.append('SameSite=None')
            lines.append('; '.join(parts))
        return lines
