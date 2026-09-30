"""
Crawler(render_js=True) delegates page fetching to crawler.browser.BrowserSession
instead of `requests`. These tests fake BrowserSession out entirely (no real
Chromium involved -- see tests/test_browser.py for BrowserSession's own unit
tests) so the crawl orchestration (BFS, scope/depth checks, login, cookie
syncing, storage-state saving) can be verified in isolation.
"""
import requests

import crawler.browser as browser_module
from crawler.browser import BrowserFetchResult
from crawler.spider import Crawler


class FakeBrowserSession:
    """Records every call so tests can assert on how Crawler drives it, and
    serves canned BrowserFetchResults keyed by URL."""
    last_instance = None

    def __init__(self, proxy=None, extra_headers=None, seed_cookies=None, storage_state=None, **perf_options):
        self.perf_options = perf_options
        self.proxy = proxy
        self.extra_headers = extra_headers
        self.seed_cookies = seed_cookies
        self.storage_state = storage_state
        self.login_calls = []
        self.sync_calls = []
        self.saved_paths = []
        self.responses = {}
        FakeBrowserSession.last_instance = self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def login(self, **kwargs):
        self.login_calls.append(kwargs)

    def sync_cookies_into(self, session):
        self.sync_calls.append(session)

    def save_storage_state(self, path):
        self.saved_paths.append(path)

    def get(self, url, timeout=10):
        return self.responses.get(
            url, BrowserFetchResult(200, url, 'text/html', {}, '<html><body></body></html>')
        )


def test_render_js_crawls_via_browser_and_follows_rendered_links(monkeypatch):
    c = Crawler('https://example.com/', depth=1, render_js=True)

    # Crawler always builds a fresh BrowserSession inside crawl(); pre-seed
    # its canned responses via a small subclass closure.
    responses = {
        'https://example.com/': BrowserFetchResult(
            200, 'https://example.com/', 'text/html', {},
            '<html><body><a href="/next">next</a><script src="/app.js"></script></body></html>',
        ),
        'https://example.com/next': BrowserFetchResult(200, 'https://example.com/next', 'text/html', {}, '<html></html>'),
    }

    class SeededFakeBrowserSession(FakeBrowserSession):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.responses = responses

    monkeypatch.setattr(browser_module, 'BrowserSession', SeededFakeBrowserSession)

    pages = c.crawl()

    urls = {p.url for p in pages}
    assert urls == {'https://example.com/', 'https://example.com/next'}
    home = next(p for p in pages if p.url == 'https://example.com/')
    assert home.scripts == ['https://example.com/app.js']
    assert home.links == ['https://example.com/next']


def test_render_js_respects_depth_and_scope(monkeypatch):
    responses = {
        'https://example.com/': BrowserFetchResult(
            200, 'https://example.com/', 'text/html', {},
            '<html><body><a href="/deep">deep</a><a href="https://other.com/x">off-site</a></body></html>',
        ),
        'https://example.com/deep': BrowserFetchResult(
            200, 'https://example.com/deep', 'text/html', {},
            '<html><body><a href="/too-deep">too deep</a></body></html>',
        ),
    }

    class SeededFakeBrowserSession(FakeBrowserSession):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.responses = responses

    monkeypatch.setattr(browser_module, 'BrowserSession', SeededFakeBrowserSession)

    c = Crawler('https://example.com/', depth=1, render_js=True)
    pages = c.crawl()

    urls = {p.url for p in pages}
    assert urls == {'https://example.com/', 'https://example.com/deep'}  # depth 1 stops before /too-deep
    assert 'https://other.com/x' not in urls  # out of scope


def test_render_js_fetch_error_becomes_an_error_pageresult(monkeypatch):
    responses = {
        'https://example.com/': BrowserFetchResult(None, 'https://example.com/', '', {}, '', error='navigation timed out'),
    }

    class SeededFakeBrowserSession(FakeBrowserSession):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.responses = responses

    monkeypatch.setattr(browser_module, 'BrowserSession', SeededFakeBrowserSession)

    c = Crawler('https://example.com/', render_js=True)
    pages = c.crawl()

    assert len(pages) == 1
    assert pages[0].status is None
    assert pages[0].error == 'navigation timed out'


def test_render_js_runs_login_before_crawling_and_syncs_cookies_twice(monkeypatch):
    monkeypatch.setattr(browser_module, 'BrowserSession', FakeBrowserSession)
    login = {'login_url': 'https://example.com/login', 'user': 'alice', 'password': 'hunter2'}
    c = Crawler('https://example.com', render_js=True, login=login)

    c.crawl()

    session_instance = FakeBrowserSession.last_instance
    assert session_instance.login_calls == [dict(login, timeout=c.timeout)]
    # once right after login, once more after the crawl to catch cookie rotation
    assert session_instance.sync_calls == [c.session, c.session]


def test_render_js_saves_storage_state_when_requested(monkeypatch):
    monkeypatch.setattr(browser_module, 'BrowserSession', FakeBrowserSession)
    c = Crawler('https://example.com', render_js=True, save_storage_state='out/state.json')

    c.crawl()

    assert FakeBrowserSession.last_instance.saved_paths == ['out/state.json']


def test_render_js_does_not_save_storage_state_when_not_requested(monkeypatch):
    monkeypatch.setattr(browser_module, 'BrowserSession', FakeBrowserSession)
    c = Crawler('https://example.com/', render_js=True)

    c.crawl()

    assert FakeBrowserSession.last_instance.saved_paths == []


def test_render_js_seeds_the_browser_with_session_headers_and_cookies(monkeypatch):
    monkeypatch.setattr(browser_module, 'BrowserSession', FakeBrowserSession)
    c = Crawler('https://example.com', render_js=True,
                headers={'Authorization': 'Bearer abc'}, cookies={'session': 'xyz'},
                storage_state='state.json')

    c.crawl()

    session_instance = FakeBrowserSession.last_instance
    assert session_instance.extra_headers['Authorization'] == 'Bearer abc'
    assert any(getattr(ck, 'name', None) == 'session' for ck in session_instance.seed_cookies)
    assert session_instance.storage_state == 'state.json'


def test_default_crawl_still_uses_requests_when_render_js_is_false():
    # Sanity check that the two code paths stay properly gated: without
    # render_js, Crawler never touches crawler.browser at all.
    c = Crawler('https://example.com')
    assert c.render_js is False
    assert isinstance(c.session, requests.Session)


def test_render_performance_options_are_forwarded_to_the_browser_session(monkeypatch):
    monkeypatch.setattr(browser_module, 'BrowserSession', FakeBrowserSession)
    Crawler('https://example.com', depth=0, render_js=True,
            block_stylesheets=False, neutralize_canvas=True,
            browser_arg=['--no-sandbox']).crawl()
    opts = FakeBrowserSession.last_instance.perf_options
    assert opts['block_resources'] is True
    assert opts['block_stylesheets'] is False
    assert opts['block_trackers'] is True
    assert opts['neutralize_canvas'] is True
    assert opts['extra_launch_args'] == ['--no-sandbox']
