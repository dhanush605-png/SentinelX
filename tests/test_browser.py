"""
crawler.browser.BrowserSession wraps Playwright. These tests fake out
Playwright's sync API entirely (no real browser download/launch needed) so
the session-management, login, and cookie-translation logic can be verified
in isolation -- the same fake-the-network philosophy the rest of the test
suite uses for `requests`.
"""
import sys
import types

import pytest

from crawler.browser import BrowserSession


class FakeResponse:
    def __init__(self, status=200, headers=None):
        self.status = status
        self.headers = headers if headers is not None else {'content-type': 'text/html; charset=utf-8'}


class FakePage:
    def __init__(self):
        self.url = None
        self.goto_calls = []
        self.fill_calls = []
        self.click_calls = []
        self.wait_for_selector_calls = []
        self.content_html = '<html><body><a href="/next">next</a></body></html>'
        self.response = FakeResponse()
        self.closed = False

    def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append({'url': url, 'wait_until': wait_until, 'timeout': timeout})
        self.url = url
        return self.response

    def fill(self, selector, value, timeout=None):
        self.fill_calls.append((selector, value))

    def click(self, selector, timeout=None):
        self.click_calls.append(selector)

    def wait_for_selector(self, selector, timeout=None):
        self.wait_for_selector_calls.append(selector)

    def wait_for_load_state(self, state, timeout=None):
        pass

    def content(self):
        return self.content_html

    def close(self):
        self.closed = True


class FakeRequest:
    def __init__(self, url, resource_type):
        self.url = url
        self.resource_type = resource_type


class FakeRoute:
    def __init__(self, url, resource_type):
        self.request = FakeRequest(url, resource_type)
        self.aborted = False
        self.continued = False

    def abort(self):
        self.aborted = True

    def continue_(self):
        self.continued = True


class FakeContext:
    def __init__(self):
        self.pages = []
        self.extra_headers = None
        self.added_cookies = []
        self._cookies = []
        self.storage_state_path = None
        self.closed = False
        self.kwargs = {}
        self.routes = []
        self.init_scripts = []

    def new_page(self):
        p = FakePage()
        self.pages.append(p)
        return p

    def set_extra_http_headers(self, headers):
        self.extra_headers = headers

    def add_cookies(self, cookies):
        self.added_cookies.extend(cookies)
        self._cookies.extend(cookies)

    def cookies(self, url=None):
        return list(self._cookies)

    def storage_state(self, path=None):
        self.storage_state_path = path

    def route(self, pattern, handler):
        self.routes.append((pattern, handler))

    def add_init_script(self, script):
        self.init_scripts.append(script)

    def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self):
        self.contexts = []
        self.closed = False
        self.launch_kwargs = {}

    def new_context(self, **kwargs):
        ctx = FakeContext()
        ctx.kwargs = kwargs
        self.contexts.append(ctx)
        return ctx

    def close(self):
        self.closed = True


class FakeChromium:
    def __init__(self):
        self.launched = []

    def launch(self, headless=True, **kwargs):
        b = FakeBrowser()
        b.launch_kwargs = kwargs
        self.launched.append(b)
        return b


class FakePlaywright:
    def __init__(self):
        self.chromium = FakeChromium()


class FakePlaywrightContextManager:
    def __init__(self):
        self.pw = FakePlaywright()
        self.exited = False

    def __enter__(self):
        return self.pw

    def __exit__(self, *exc):
        self.exited = True
        return False


@pytest.fixture(autouse=True)
def fake_playwright(monkeypatch):
    """Install a fake `playwright.sync_api` module so BrowserSession's
    lazy `from playwright.sync_api import sync_playwright` import resolves
    to our fakes instead of requiring the real package + browser binary."""
    fake_sync_api = types.ModuleType('playwright.sync_api')
    fake_sync_api.sync_playwright = lambda: FakePlaywrightContextManager()
    fake_pkg = types.ModuleType('playwright')
    fake_pkg.sync_api = fake_sync_api
    monkeypatch.setitem(sys.modules, 'playwright', fake_pkg)
    monkeypatch.setitem(sys.modules, 'playwright.sync_api', fake_sync_api)
    yield


class _Cookie:
    """Mimics one entry of a requests.cookies.RequestsCookieJar."""
    def __init__(self, name, value, domain='example.com', path='/'):
        self.name, self.value, self.domain, self.path = name, value, domain, path


def test_context_manager_launches_and_tears_down_cleanly():
    with BrowserSession() as browser:
        assert browser._browser is not None
        assert browser._context is not None
    assert browser._context.closed
    assert browser._browser.closed


def test_proxy_is_passed_to_chromium_launch():
    with BrowserSession(proxy='http://myproxy:3128') as browser:
        assert browser._browser.launch_kwargs['proxy'] == {'server': 'http://myproxy:3128'}


def test_default_engine_args_are_passed_to_chromium_launch():
    from crawler.browser import DEFAULT_ENGINE_ARGS
    with BrowserSession() as browser:
        args = browser._browser.launch_kwargs['args']
        for flag in DEFAULT_ENGINE_ARGS:
            assert flag in args
        # A weakened sandbox is opt-in only, never a silent default.
        assert '--no-sandbox' not in args


def test_extra_launch_args_are_appended():
    with BrowserSession(extra_launch_args=['--no-sandbox']) as browser:
        assert browser._browser.launch_kwargs['args'][-1] == '--no-sandbox'


def test_extra_headers_excluding_user_agent_are_set_on_the_context():
    with BrowserSession(extra_headers={'User-Agent': 'SentinelX/1.0', 'Authorization': 'Bearer abc'}) as browser:
        assert browser._context.extra_headers == {'Authorization': 'Bearer abc'}
        assert browser._context.kwargs['user_agent'] == 'SentinelX/1.0'


def test_storage_state_path_is_forwarded_to_new_context():
    with BrowserSession(storage_state='state.json') as browser:
        assert browser._context.kwargs['storage_state'] == 'state.json'


def test_seed_cookies_without_a_domain_are_skipped():
    cookies = [_Cookie('has_domain', 'v1', domain='example.com'), _Cookie('no_domain', 'v2', domain='')]
    with BrowserSession(seed_cookies=cookies) as browser:
        names = {c['name'] for c in browser._context.added_cookies}
        assert names == {'has_domain'}


def test_login_fills_username_and_password_and_submits():
    with BrowserSession() as browser:
        browser.login('https://example.com/login', 'alice', 'hunter2',
                       user_selector='#user', pass_selector='#pass', submit_selector='#go')
        page = browser._context.pages[-1]
        assert page.goto_calls[0]['url'] == 'https://example.com/login'
        assert page.fill_calls == [('#user', 'alice'), ('#pass', 'hunter2')]
        assert page.click_calls == ['#go']
        assert page.closed


def test_login_waits_for_explicit_selector_when_given():
    with BrowserSession() as browser:
        browser.login('https://example.com/login', 'alice', 'hunter2', wait_selector='#dashboard')
        page = browser._context.pages[-1]
        assert page.wait_for_selector_calls == ['#dashboard']


def test_get_returns_status_headers_html_and_cookies():
    with BrowserSession() as browser:
        browser._context._cookies = [
            {'name': 'session', 'value': 'abc', 'secure': True, 'httpOnly': True, 'sameSite': 'Strict'},
        ]
        result = browser.get('https://example.com/')
        assert result.status == 200
        assert result.content_type == 'text/html; charset=utf-8'
        assert 'next' in result.html
        assert result.error is None
        assert result.set_cookie_headers == ['session=abc; Secure; HttpOnly; SameSite=Strict']


def test_get_handles_no_response_as_an_error():
    with BrowserSession() as browser:
        page = browser._context.new_page()
        # Simulate Playwright returning None for e.g. a same-page anchor
        # navigation by pre-seeding the *next* new_page() call.
        browser._context.new_page = lambda: _NoResponsePage()
        result = browser.get('https://example.com/#anchor')
        assert result.status is None
        assert 'no response' in result.error


class _NoResponsePage(FakePage):
    def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append({'url': url, 'wait_until': wait_until, 'timeout': timeout})
        return None


def test_get_captures_exceptions_as_errors_instead_of_raising():
    with BrowserSession() as browser:
        def boom():
            page = FakePage()
            def raise_goto(*a, **k):
                raise TimeoutError('navigation timed out')
            page.goto = raise_goto
            return page
        browser._context.new_page = boom
        result = browser.get('https://example.com/slow')
        assert result.status is None
        assert 'navigation timed out' in result.error


def test_sync_cookies_into_copies_context_cookies_into_a_requests_session():
    import requests
    with BrowserSession() as browser:
        browser._context._cookies = [
            {'name': 'session', 'value': 'abc', 'domain': 'example.com', 'path': '/'},
        ]
        session = requests.Session()
        browser.sync_cookies_into(session)
        assert session.cookies.get('session', domain='example.com') == 'abc'


def test_save_storage_state_writes_to_the_given_path():
    with BrowserSession() as browser:
        browser.save_storage_state('out/state.json')
        assert browser._context.storage_state_path == 'out/state.json'


def test_cookie_lines_render_samesite_none_explicitly():
    with BrowserSession() as browser:
        browser._context._cookies = [{'name': 'pref', 'value': 'dark', 'sameSite': 'None'}]
        result = browser.get('https://example.com/')
        assert result.set_cookie_headers == ['pref=dark; SameSite=None']


# --- Resource interception (performance) -----------------------------------

def test_route_is_registered_for_all_urls_by_default():
    with BrowserSession() as browser:
        patterns = [p for p, _ in browser._context.routes]
        assert patterns == ['**/*']


def test_images_media_and_fonts_are_aborted_by_default():
    with BrowserSession() as browser:
        _, handler = browser._context.routes[0]
        for resource_type in ('image', 'media', 'font'):
            route = FakeRoute('https://example.com/thing', resource_type)
            handler(route)
            assert route.aborted and not route.continued


def test_stylesheets_are_aborted_by_default_but_not_when_opted_out():
    with BrowserSession() as browser:
        _, handler = browser._context.routes[0]
        route = FakeRoute('https://example.com/site.css', 'stylesheet')
        handler(route)
        assert route.aborted

    with BrowserSession(block_stylesheets=False) as browser:
        _, handler = browser._context.routes[0]
        route = FakeRoute('https://example.com/site.css', 'stylesheet')
        handler(route)
        assert route.continued and not route.aborted


def test_scripts_and_xhr_are_never_blocked():
    with BrowserSession() as browser:
        _, handler = browser._context.routes[0]
        for resource_type in ('script', 'xhr', 'fetch', 'document', 'websocket'):
            route = FakeRoute('https://example.com/thing', resource_type)
            handler(route)
            assert route.continued and not route.aborted


def test_known_tracker_hosts_are_aborted_regardless_of_resource_type():
    with BrowserSession() as browser:
        _, handler = browser._context.routes[0]
        route = FakeRoute('https://www.google-analytics.com/collect', 'xhr')
        handler(route)
        assert route.aborted


def test_block_resources_false_disables_asset_blocking_but_keeps_tracker_blocking():
    with BrowserSession(block_resources=False) as browser:
        _, handler = browser._context.routes[0]
        image_route = FakeRoute('https://example.com/logo.png', 'image')
        handler(image_route)
        assert image_route.continued

        tracker_route = FakeRoute('https://sentry.io/api/1/store', 'xhr')
        handler(tracker_route)
        assert tracker_route.aborted


def test_no_interception_registered_when_both_blocking_flags_are_off():
    with BrowserSession(block_resources=False, block_trackers=False) as browser:
        assert browser._context.routes == []


def test_neutralize_canvas_is_opt_in_and_off_by_default():
    with BrowserSession() as browser:
        assert browser._context.init_scripts == []

    with BrowserSession(neutralize_canvas=True) as browser:
        assert len(browser._context.init_scripts) == 1
        assert 'getContext' in browser._context.init_scripts[0]
