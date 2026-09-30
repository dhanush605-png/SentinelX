from __future__ import annotations
from dataclasses import dataclass, field, asdict
from collections import deque
from urllib.parse import urljoin, urldefrag, urlparse
import logging, time, requests
from bs4 import BeautifulSoup

from crawler.session import SessionManager
from discovery.params import extract_forms

log = logging.getLogger('SentinelX')


@dataclass
class PageResult:
    url: str
    status: int | None
    final_url: str
    content_type: str
    links: list[str]
    scripts: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    set_cookie_headers: list[str] = field(default_factory=list)
    error: str | None = None
    forms: list = field(default_factory=list)  # discovery.params.Form objects

    def dict(self):
        return asdict(self)


class Crawler:
    def __init__(self, target: str, depth=2, timeout=10, rate_limit=0.0, scope='same-origin', proxy=None, *,
                 headers: dict[str, str] | None = None,
                 cookies: dict[str, str] | None = None,
                 basic_auth: tuple[str, str] | None = None,
                 render_js: bool = False,
                 storage_state: str | None = None,
                 login: dict | None = None,
                 save_storage_state: str | None = None,
                 max_reauths: int = 3,
                 auth_v2: bool = False,
                 auth_verify_url: str | None = None,
                 auth_success_text: str | None = None,
                 auth_failure_text: str | None = None,
                 block_resources: bool = True,
                 block_stylesheets: bool = True,
                 block_trackers: bool = True,
                 neutralize_canvas: bool = False,
                 browser_arg: list[str] | None = None):
        """
        headers, cookies, basic_auth: authenticate every request the crawl
            makes (custom Authorization/API-key headers, a raw session
            cookie, or HTTP Basic credentials) -- see crawler.auth for the
            CLI-argument parsers that build these.
        render_js: fetch pages with a real headless browser (see
            crawler.browser.BrowserSession) instead of a plain GET, so
            JavaScript-rendered SPA content and links are discovered too.
        storage_state: path to a Playwright storage_state JSON (cookies +
            localStorage) from an already-authenticated browser session.
            Only used when render_js is set.
        login: optional dict (login_url, user, password, user_selector,
            pass_selector, submit_selector, wait_selector) describing a
            one-shot login-form submission to run before crawling. Only
            used when render_js is set.
        save_storage_state: path to write the authenticated session to
            after login/crawl, for reuse via storage_state on a later run.
            Only used when render_js is set.
        max_reauths: how many times crawler.session.SessionManager is
            allowed to re-run the configured login if the session appears
            to expire mid-crawl (401/403, or a redirect back to a login
            page). Only takes effect when `login` is set -- static
            credentials (headers/cookies/basic_auth) have no way to renew
            themselves, so an expired one is only detected, not recovered.
        block_resources, block_stylesheets, block_trackers,
            neutralize_canvas, browser_arg: forwarded to
            crawler.browser.BrowserSession -- see its constructor
            docstring for what each controls. Only take effect when
            render_js is set.
        """
        self.target = target if '://' in target else 'https://' + target
        self.depth = depth
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.scope = scope
        self.proxy = proxy
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'SentinelX/1.0 (authorized-security-testing)'
        if headers:
            self.session.headers.update(headers)
        if cookies:
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
        if basic_auth:
            self.session.auth = basic_auth
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
        parsed = urlparse(self.target)
        self.origin = (parsed.scheme, parsed.netloc)
        self.site = parsed.hostname
        self.render_js = render_js
        self.storage_state = storage_state
        self.login = login
        self.save_storage_state_path = save_storage_state
        self.auth_v2 = auth_v2
        self.auth_verify_url = auth_verify_url
        self.auth_success_text = auth_success_text
        self.auth_failure_text = auth_failure_text
        self.block_resources = block_resources
        self.block_stylesheets = block_stylesheets
        self.block_trackers = block_trackers
        self.neutralize_canvas = neutralize_canvas
        self.browser_arg = browser_arg
        self.auth_v2_controller = None
        # No reauth_callback yet: only _crawl_with_browser can actually
        # replay a login (it requires a live BrowserSession), so it wires
        # one in via a closure once the browser exists. The plain-requests
        # path still uses this manager to *detect* and log expiry.
        self.session_manager = SessionManager(
            max_reauths=max_reauths,
            login_url_hint=self.login['login_url'] if self.login else None,
        )

    def allowed(self, url):
        p = urlparse(url)
        if p.scheme not in ('http', 'https'):
            return False
        if self.scope == 'same-origin':
            return (p.scheme, p.netloc) == self.origin
        return p.hostname == self.site or (p.hostname or '').endswith('.' + (self.site or ''))

    @staticmethod
    def _set_cookie_headers(resp) -> list[str]:
        # requests' CaseInsensitiveDict.get('set-cookie') joins multiple
        # Set-Cookie response headers into one comma-separated string, which
        # silently corrupts per-cookie parsing. raw.headers.get_all() (when
        # available, i.e. urllib3-backed responses) preserves each header
        # separately; fall back to the joined form if it isn't.
        try:
            values = resp.raw.headers.get_all('Set-Cookie')
            if values:
                return list(values)
        except AttributeError:
            pass
        single = resp.headers.get('set-cookie')
        return [single] if single else []

    @staticmethod
    def _extract_dom(html_text: str, base_url: str):
        """Pull absolute link/script URLs and HTML forms out of a page's
        DOM. Shared by both fetch backends: for a plain GET this is the
        server-rendered HTML; for --render-js it's the DOM *after* the
        page's own JavaScript has run, which is what lets an SPA's
        client-side-routed links, dynamically-inserted script tags, and
        JS-rendered forms be found at all. Returns (links, scripts, forms)."""
        soup = BeautifulSoup(html_text, 'lxml')
        links = [urljoin(base_url, a.get('href')) for a in soup.select('a[href]') if a.get('href')]
        scripts = [urljoin(base_url, s.get('src')) for s in soup.select('script[src]') if s.get('src')]
        forms = extract_forms(html_text, base_url)
        return links, scripts, forms

    def crawl(self):
        if self.render_js:
            return self._crawl_with_browser()
        return self._crawl_with_requests()

    def _crawl_with_requests(self):
        q = deque([(self.target, 0)])
        seen = set()
        results = []
        while q:
            url, d = q.popleft()
            url = urldefrag(url)[0]
            if url in seen or d > self.depth or not self.allowed(url):
                continue
            seen.add(url)
            try:
                if self.rate_limit:
                    time.sleep(self.rate_limit)
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if self.session_manager.maybe_reauth(r.status_code, r.url):
                    r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                links, scripts, forms = [], [], []
                if 'text/html' in r.headers.get('content-type', '').lower():
                    links, scripts, forms = self._extract_dom(r.text, r.url)
                    for link in links:
                        if self.allowed(link) and link not in seen:
                            q.append((link, d + 1))
                results.append(PageResult(
                    url=url,
                    status=r.status_code,
                    final_url=r.url,
                    content_type=r.headers.get('content-type', ''),
                    links=links,
                    scripts=scripts,
                    headers={k: v for k, v in r.headers.items()},
                    set_cookie_headers=self._set_cookie_headers(r),
                    forms=forms,
                ))
            except requests.RequestException as e:
                results.append(PageResult(url, None, url, '', [], error=str(e)))
        return results

    def _crawl_with_browser(self):
        # Imported lazily: Playwright is only required when --render-js is
        # actually used, so a plain crawl doesn't need it installed at all.
        from crawler.browser import BrowserSession

        with BrowserSession(proxy=self.proxy, extra_headers=dict(self.session.headers),
                             seed_cookies=list(self.session.cookies),
                             storage_state=self.storage_state,
                             block_resources=self.block_resources,
                             block_stylesheets=self.block_stylesheets,
                             block_trackers=self.block_trackers,
                             neutralize_canvas=self.neutralize_canvas,
                             extra_launch_args=self.browser_arg) as browser:
            if self.auth_v2:
                if not self.login:
                    raise ValueError('--auth-v2 requires --login-url, --login-user and a password')
                if not self.auth_verify_url:
                    raise ValueError('--auth-v2 requires --auth-verify-url')
                from crawler.auth_v2 import AuthenticationController

                def _login_v2() -> bool:
                    try:
                        browser.login(**self.login, timeout=self.timeout)
                        browser.sync_cookies_into(self.session)
                        return True
                    except Exception as e:
                        log.warning('Auth V2 login failed: %s', e)
                        return False

                verify_url = urljoin(self.target, self.auth_verify_url)

                def _verify_v2() -> bool:
                    check = browser.get(verify_url, timeout=self.timeout)
                    if check.error or check.status in (401, 403):
                        return False
                    body = check.html or ''
                    if self.auth_failure_text and self.auth_failure_text.lower() in body.lower():
                        return False
                    if self.auth_success_text and self.auth_success_text.lower() not in body.lower():
                        return False
                    return check.status is not None and check.status < 400

                self.auth_v2_controller = AuthenticationController(
                    login_callback=_login_v2,
                    verify_callback=_verify_v2,
                    max_reauths=self.session_manager.max_reauths,
                )
                if not self.auth_v2_controller.initial_login():
                    raise RuntimeError('Auth V2 initial authentication or verification failed')
            elif self.login:
                browser.login(**self.login, timeout=self.timeout)

                def _reauth() -> bool:
                    try:
                        browser.login(**self.login, timeout=self.timeout)
                        browser.sync_cookies_into(self.session)
                        return True
                    except Exception as e:
                        log.warning('re-login attempt failed: %s', e)
                        return False

                self.session_manager.reauth_callback = _reauth
            # Whatever authenticated the browser (a loaded storage_state or
            # a login-form submission) becomes the *one* authenticated
            # identity for the whole run: copy it into self.session so the
            # plain-requests calls main.py makes outside of crawl() (JS-file
            # fetches, endpoint-discovery probes, CORS probing) ride the
            # same session as the rendered pages, rather than falling back
            # to an anonymous request.
            browser.sync_cookies_into(self.session)

            q = deque([(self.target, 0)])
            seen = set()
            results = []
            while q:
                url, d = q.popleft()
                url = urldefrag(url)[0]
                if url in seen or d > self.depth or not self.allowed(url):
                    continue
                seen.add(url)
                if self.rate_limit:
                    time.sleep(self.rate_limit)
                fetched = browser.get(url, timeout=self.timeout)
                if self.auth_v2 and not fetched.error and self.auth_v2_controller:
                    if self.auth_v2_controller.is_expired(
                            fetched.status, fetched.final_url, self.login['login_url'],
                            body=fetched.html, failure_text=self.auth_failure_text):
                        if self.auth_v2_controller.reauthenticate(
                                f'HTTP {fetched.status}' if fetched.status in (401, 403) else 'login redirect'):
                            browser.sync_cookies_into(self.session)
                            fetched = browser.get(url, timeout=self.timeout)
                elif not self.auth_v2 and not fetched.error and self.session_manager.maybe_reauth(fetched.status, fetched.final_url):
                    fetched = browser.get(url, timeout=self.timeout)
                if fetched.error:
                    results.append(PageResult(url, None, url, '', [], error=fetched.error))
                    continue
                links, scripts, forms = [], [], []
                if 'text/html' in (fetched.content_type or '').lower() or not fetched.content_type:
                    links, scripts, forms = self._extract_dom(fetched.html, fetched.final_url)
                    for link in links:
                        if self.allowed(link) and link not in seen:
                            q.append((link, d + 1))
                results.append(PageResult(
                    url=url,
                    status=fetched.status,
                    final_url=fetched.final_url,
                    content_type=fetched.content_type,
                    links=links,
                    scripts=scripts,
                    headers=fetched.headers,
                    set_cookie_headers=fetched.set_cookie_headers,
                    forms=forms,
                ))

            # Cookies can rotate during the crawl (CSRF tokens, session
            # renewal); resync once more before the browser context closes
            # so main.py's post-crawl requests see the final state.
            browser.sync_cookies_into(self.session)
            if self.save_storage_state_path:
                browser.save_storage_state(self.save_storage_state_path)

            return results
