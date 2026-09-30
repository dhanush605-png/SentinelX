"""
build_report() is the orchestration function that main() calls -- it runs
the crawler and every discovery/analysis module and buckets the results
into per-feature sections. These tests fake out the network entirely
(a fake Crawler + fake requests.Session) so the categorization logic can be
verified without hitting a real site.
"""
import argparse

import requests
from requests.structures import CaseInsensitiveDict

import main as main_module
from crawler.spider import PageResult


def _args(**overrides):
    defaults = dict(depth=2, timeout=5, rate_limit=0.0, scope='same-origin', proxy=None, format='all', output='reports')
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class _FakeResponse:
    def __init__(self, status_code=200, text='', headers=None):
        self.status_code = status_code
        self.text = text
        # requests.Response.headers is case-insensitive in real usage;
        # analysis.security.check_cors relies on that, so the fake must match.
        self.headers = CaseInsensitiveDict(headers or {})


class _FakeSession:
    """Serves canned responses for the extra requests build_report() makes
    beyond the crawl itself: endpoint-discovery probes, JS fetches, and
    CORS probes -- all keyed by URL."""

    def __init__(self, responses):
        self._responses = responses

    def get(self, url, timeout=None, headers=None):
        if url not in self._responses:
            raise requests.ConnectionError(f'no fake response configured for {url}')
        resp = self._responses[url]
        if isinstance(resp, Exception):
            raise resp
        return resp


class _FakeCrawler:
    def __init__(self, target, depth, timeout, rate_limit, scope, proxy, pages, session, **auth_kwargs):
        self.target = target
        self.session = session
        self._pages = pages
        # Recorded so tests can assert on how build_report() wired up
        # authentication/render-js, without every existing test needing to
        # care about these kwargs.
        self.auth_kwargs = auth_kwargs

    def crawl(self):
        return self._pages


def _install_fake_crawler(monkeypatch, pages, session):
    def factory(target, depth, timeout, rate_limit, scope, proxy, **auth_kwargs):
        return _FakeCrawler(target, depth, timeout, rate_limit, scope, proxy, pages, session, **auth_kwargs)
    monkeypatch.setattr(main_module, 'Crawler', factory)


def _section(report, section_id):
    return next(s for s in report['sections'] if s['id'] == section_id)


def test_categorizes_broken_links_redirects_and_ok_pages(monkeypatch):
    pages = [
        PageResult('http://t/', 200, 'http://t/', 'text/html', links=[], headers={}),
        PageResult('http://t/missing', 404, 'http://t/missing', 'text/html', links=[], headers={}),
        PageResult('http://t/old', 301, 'http://t/new', 'text/html', links=[], headers={}),
        PageResult('http://t/timeout', None, 'http://t/timeout', '', links=[], error='Connection timed out'),
    ]
    session = _FakeSession({})  # no interesting-paths/JS/CORS targets exist here
    for path in ['http://t/robots.txt', 'http://t/sitemap.xml', 'http://t/swagger.json',
                 'http://t/openapi.json', 'http://t/swagger/index.html', 'http://t/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args())

    broken = {r['URL'] for r in _section(report, 'broken_links')['rows']}
    assert broken == {'http://t/missing', 'http://t/timeout'}

    redirects = {r['URL'] for r in _section(report, 'redirects')['rows']}
    assert redirects == {'http://t/old'}

    crawl_urls = {r['URL'] for r in _section(report, 'crawl')['rows']}
    assert crawl_urls == {p.url for p in pages}


def test_hidden_js_endpoint_is_fetched_live_and_probed_for_cors(monkeypatch):
    # A hidden endpoint (referenced only in JS, not linked from any crawled
    # page) is still a real, directly-reachable URL -- SentinelX should fetch
    # it for API Discovery's status column AND probe it for CORS, exactly
    # like a linked endpoint, rather than treating "not linked" as "not
    # checked". This is also the case that matters most in practice: an
    # endpoint deliberately left unlinked is often the one worth probing.
    pages = [
        PageResult('http://t/', 200, 'http://t/', 'text/html', links=[], scripts=['http://t/app.js'], headers={}),
    ]
    session = _FakeSession({
        'http://t/app.js': _FakeResponse(text='fetch("/api/internal/debug")'),
        'http://t/api/internal/debug': _FakeResponse(status_code=200, headers={
            'Access-Control-Allow-Origin': 'https://cors-probe.SentinelX.invalid',
            'Access-Control-Allow-Credentials': 'true',
        }),
    })
    for path in ['http://t/robots.txt', 'http://t/sitemap.xml', 'http://t/swagger.json',
                 'http://t/openapi.json', 'http://t/swagger/index.html', 'http://t/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args())

    js_rows = _section(report, 'js_analysis')['rows']
    assert js_rows[0]['Script'] == 'http://t/app.js'
    assert 'http://t/api/internal/debug' in js_rows[0]['Endpoints Found']

    api_rows = {r['URL']: r for r in _section(report, 'api_discovery')['rows']}
    assert api_rows['http://t/api/internal/debug']['Status'] == 200
    assert 'JavaScript' in api_rows['http://t/api/internal/debug']['Linked']

    cors_rows = {r['URL']: r for r in _section(report, 'cors')['rows']}
    assert 'YES' in cors_rows['http://t/api/internal/debug']['High Risk']


def test_cors_high_risk_reflection_is_flagged(monkeypatch):
    pages = [
        PageResult('http://t/api/status', 200, 'http://t/api/status', 'application/json', links=[], headers={}),
    ]
    session = _FakeSession({
        'http://t/api/status': _FakeResponse(headers={
            'Access-Control-Allow-Origin': 'https://cors-probe.SentinelX.invalid',
            'Access-Control-Allow-Credentials': 'true',
        }),
    })
    for path in ['http://t/robots.txt', 'http://t/sitemap.xml', 'http://t/swagger.json',
                 'http://t/openapi.json', 'http://t/swagger/index.html', 'http://t/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args())

    cors_rows = _section(report, 'cors')['rows']
    assert len(cors_rows) == 1
    assert 'YES' in cors_rows[0]['High Risk']


def test_cookie_issues_are_surfaced_and_deduplicated(monkeypatch):
    pages = [
        PageResult('http://t/', 200, 'http://t/', 'text/html', links=[], headers={},
                   set_cookie_headers=['tracking_id=abc; Path=/']),
        PageResult('http://t/about', 200, 'http://t/about', 'text/html', links=[], headers={},
                   set_cookie_headers=['tracking_id=abc; Path=/']),  # same cookie again elsewhere
    ]
    session = _FakeSession({})
    for path in ['http://t/robots.txt', 'http://t/sitemap.xml', 'http://t/swagger.json',
                 'http://t/openapi.json', 'http://t/swagger/index.html', 'http://t/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args())

    cookie_rows = _section(report, 'cookies')['rows']
    assert len(cookie_rows) == 1  # deduplicated by name
    assert cookie_rows[0]['Cookie'] == 'tracking_id'
    assert 'Missing HttpOnly' in cookie_rows[0]['Issues']


def test_passive_subdomains_marked_not_applicable_for_ip_target(monkeypatch):
    pages = [PageResult('http://127.0.0.1/', 200, 'http://127.0.0.1/', 'text/html', links=[], headers={})]
    session = _FakeSession({})
    for path in ['http://127.0.0.1/robots.txt', 'http://127.0.0.1/sitemap.xml', 'http://127.0.0.1/swagger.json',
                 'http://127.0.0.1/openapi.json', 'http://127.0.0.1/swagger/index.html', 'http://127.0.0.1/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://127.0.0.1', _args())

    passive = _section(report, 'passive_subdomains')
    assert passive['count'] == 0
    assert passive['not_applicable'] is not None
    assert 'not a public' in passive['not_applicable']


def test_passive_subdomains_populated_for_a_public_hostname(monkeypatch):
    pages = [PageResult('http://example.com/', 200, 'http://example.com/', 'text/html', links=[], headers={})]
    session = _FakeSession({})
    for path in ['http://example.com/robots.txt', 'http://example.com/sitemap.xml', 'http://example.com/swagger.json',
                 'http://example.com/openapi.json', 'http://example.com/swagger/index.html', 'http://example.com/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    _install_fake_crawler(monkeypatch, pages, session)
    monkeypatch.setattr(main_module, 'discover_passive_subdomains', lambda host, timeout=10: ['api.example.com'])

    report = main_module.build_report('http://example.com', _args())

    passive = _section(report, 'passive_subdomains')
    assert passive['not_applicable'] is None
    assert passive['rows'] == [{'Subdomain': 'api.example.com'}]


def test_auth_and_render_js_kwargs_are_forwarded_to_the_crawler(monkeypatch):
    pages = [PageResult('http://t/', 200, 'http://t/', 'text/html', links=[], headers={})]
    session = _FakeSession({})
    for path in ['http://t/robots.txt', 'http://t/sitemap.xml', 'http://t/swagger.json',
                 'http://t/openapi.json', 'http://t/swagger/index.html', 'http://t/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    captured = {}

    def factory(target, depth, timeout, rate_limit, scope, proxy, **auth_kwargs):
        captured.update(auth_kwargs)
        return _FakeCrawler(target, depth, timeout, rate_limit, scope, proxy, pages, session, **auth_kwargs)
    monkeypatch.setattr(main_module, 'Crawler', factory)

    main_module.build_report('http://t', _args(
        render_js=True,
        header=['Authorization: Bearer abc123'],
        cookie='session=xyz',
        basic_auth='alice:hunter2',
    ))

    assert captured['render_js'] is True
    assert captured['headers'] == {'Authorization': 'Bearer abc123'}
    assert captured['cookies'] == {'session': 'xyz'}
    assert captured['basic_auth'] == ('alice', 'hunter2')
    assert captured['login'] is None


def test_defaults_produce_no_auth_and_render_js_off(monkeypatch):
    pages = [PageResult('http://t/', 200, 'http://t/', 'text/html', links=[], headers={})]
    session = _FakeSession({})
    for path in ['http://t/robots.txt', 'http://t/sitemap.xml', 'http://t/swagger.json',
                 'http://t/openapi.json', 'http://t/swagger/index.html', 'http://t/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    captured = {}

    def factory(target, depth, timeout, rate_limit, scope, proxy, **auth_kwargs):
        captured.update(auth_kwargs)
        return _FakeCrawler(target, depth, timeout, rate_limit, scope, proxy, pages, session, **auth_kwargs)
    monkeypatch.setattr(main_module, 'Crawler', factory)

    main_module.build_report('http://t', _args())

    assert captured == {
        'headers': {}, 'cookies': {}, 'basic_auth': None,
        'render_js': False, 'storage_state': None, 'login': None,
        'save_storage_state': None,
        # Fast render defaults: assets/trackers blocked, canvas untouched.
        'block_resources': True, 'block_stylesheets': True, 'block_trackers': True,
        'neutralize_canvas': False, 'browser_arg': None,
    }


def test_render_performance_cli_flags_map_to_crawler_kwargs():
    kwargs = main_module._build_auth_kwargs(_args(
        render_js=True, render_assets=True, render_css=True, allow_trackers=True,
        neutralize_canvas=True, browser_arg=['--no-sandbox'],
    ))
    assert kwargs['block_resources'] is False
    assert kwargs['block_stylesheets'] is False
    assert kwargs['block_trackers'] is False
    assert kwargs['neutralize_canvas'] is True
    assert kwargs['browser_arg'] == ['--no-sandbox']


def test_login_url_without_render_js_is_rejected():
    try:
        main_module.build_report('http://t', _args(login_url='http://t/login', login_user='a', login_pass='b'))
        assert False, 'expected SystemExit'
    except SystemExit as e:
        assert '--render-js' in str(e)


def test_auth_storage_state_without_render_js_is_rejected():
    try:
        main_module.build_report('http://t', _args(auth_storage_state='state.json'))
        assert False, 'expected SystemExit'
    except SystemExit as e:
        assert '--render-js' in str(e)


def test_login_url_without_credentials_is_rejected():
    try:
        main_module.build_report('http://t', _args(render_js=True, login_url='http://t/login'))
        assert False, 'expected SystemExit'
    except SystemExit as e:
        assert 'username' in str(e) or 'password' in str(e)


def test_login_pass_env_reads_from_environment(monkeypatch):
    pages = [PageResult('http://t/', 200, 'http://t/', 'text/html', links=[], headers={})]
    session = _FakeSession({})
    for path in ['http://t/robots.txt', 'http://t/sitemap.xml', 'http://t/swagger.json',
                 'http://t/openapi.json', 'http://t/swagger/index.html', 'http://t/api-docs']:
        session._responses[path] = requests.ConnectionError('not found')
    captured = {}

    def factory(target, depth, timeout, rate_limit, scope, proxy, **auth_kwargs):
        captured.update(auth_kwargs)
        return _FakeCrawler(target, depth, timeout, rate_limit, scope, proxy, pages, session, **auth_kwargs)
    monkeypatch.setattr(main_module, 'Crawler', factory)
    monkeypatch.setenv('SentinelX_TEST_PASSWORD', 'hunter2')

    main_module.build_report('http://t', _args(
        render_js=True, login_url='http://t/login', login_user='alice', login_pass_env='SentinelX_TEST_PASSWORD',
        login_user_selector='input[name=username]', login_pass_selector='input[name=password]',
        login_submit_selector='button', login_wait=None,
    ))

    assert captured['login']['user'] == 'alice'
    assert captured['login']['password'] == 'hunter2'


def test_login_pass_env_missing_variable_is_rejected(monkeypatch):
    monkeypatch.delenv('SentinelX_TEST_MISSING', raising=False)
    try:
        main_module.build_report('http://t', _args(
            render_js=True, login_url='http://t/login', login_user='alice',
            login_pass_env='SentinelX_TEST_MISSING',
            login_user_selector='x', login_pass_selector='y', login_submit_selector='z', login_wait=None,
        ))
        assert False, 'expected SystemExit'
    except SystemExit as e:
        assert 'SentinelX_TEST_MISSING' in str(e)


def test_endpoint_discovery_only_lists_reachable_paths(monkeypatch):
    pages = [PageResult('http://t/', 200, 'http://t/', 'text/html', links=[], headers={})]
    session = _FakeSession({
        'http://t/robots.txt': _FakeResponse(status_code=200),
        'http://t/sitemap.xml': requests.ConnectionError('not found'),
        'http://t/swagger.json': _FakeResponse(status_code=404),
        'http://t/openapi.json': requests.ConnectionError('not found'),
        'http://t/swagger/index.html': requests.ConnectionError('not found'),
        'http://t/api-docs': requests.ConnectionError('not found'),
    })
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args())

    endpoint_rows = _section(report, 'endpoint_discovery')['rows']
    assert endpoint_rows == [{'URL': 'http://t/robots.txt', 'Status': 200}]


_DISCOVERY_PATHS = ['robots.txt', 'sitemap.xml', 'swagger.json', 'openapi.json',
                    'swagger/index.html', 'api-docs']


def _no_discovery(session, base='http://t/'):
    for path in _DISCOVERY_PATHS:
        session._responses[base + path] = requests.ConnectionError('not found')


def test_parameter_discovery_enumerates_query_and_form_params(monkeypatch):
    from discovery.params import extract_forms
    forms = extract_forms('<form action="/login" method="post"><input name="pw"></form>', 'http://t/')
    pages = [
        PageResult('http://t/', 200, 'http://t/', 'text/html',
                   links=['http://t/search?q=x&page=2'], forms=forms, headers={}),
    ]
    session = _FakeSession({})
    _no_discovery(session)
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args())
    params = {r['Parameter']: r for r in _section(report, 'parameters')['rows']}
    assert set(params) >= {'q', 'page', 'pw'}
    assert params['pw']['Where'] == 'form'
    assert 'POST' in params['pw']['Methods']
    assert params['page']['Where'] == 'query'


def test_source_map_endpoints_are_mined_and_probed(monkeypatch):
    import json
    map_text = json.dumps({
        'version': 3,
        'sources': ['src/api.js'],
        'sourcesContent': ["fetch('/api/secret/config')"],
    })
    pages = [
        PageResult('http://t/', 200, 'http://t/', 'text/html', links=[],
                   scripts=['http://t/app.js'], headers={}),
    ]
    session = _FakeSession({
        'http://t/app.js': _FakeResponse(text='var x=1;\n//# sourceMappingURL=app.js.map'),
        'http://t/app.js.map': _FakeResponse(text=map_text),
        # The mined endpoint is fetched live for API Discovery + CORS probe:
        'http://t/api/secret/config': _FakeResponse(status_code=200),
    })
    _no_discovery(session)
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args())

    dyn = _section(report, 'js_dynamic')['rows']
    kinds = {r['Kind'] for r in dyn}
    assert 'source map' in kinds
    assert any(r['Endpoint / Source'] == 'src/api.js' for r in dyn)

    api_rows = {r['URL']: r for r in _section(report, 'api_discovery')['rows']}
    assert 'http://t/api/secret/config' in api_rows
    assert 'JavaScript' in api_rows['http://t/api/secret/config']['Linked']


def test_template_endpoints_are_reported_but_not_fetched(monkeypatch):
    pages = [
        PageResult('http://t/', 200, 'http://t/', 'text/html', links=[],
                   scripts=['http://t/app.js'], headers={}),
    ]
    session = _FakeSession({
        # Template path with a placeholder -- must NOT be fetched live (a URL
        # with {} in it isn't real), only reported as a dynamic lead.
        'http://t/app.js': _FakeResponse(text="fetch(`/api/users/${id}`)"),
    })
    _no_discovery(session)
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args())

    dyn = _section(report, 'js_dynamic')['rows']
    assert any('http://t/api/users/{}' == r['Endpoint / Source'] for r in dyn)
    # The placeholder URL is a template lead, never a live API/CORS fetch.
    api_urls = {r['URL'] for r in _section(report, 'api_discovery')['rows']}
    assert not any('{}' in u for u in api_urls)


def test_active_param_probe_runs_only_when_enabled(monkeypatch):
    pages = [PageResult('http://t/', 200, 'http://t/', 'text/html', links=[], headers={})]

    class _ReflectingSession(_FakeSession):
        def __init__(self):
            super().__init__({})
            self.calls = []

        def get(self, url, timeout=None, headers=None):
            self.calls.append(url)
            from urllib.parse import urlparse, parse_qsl
            q = dict(parse_qsl(urlparse(url).query))
            for path in _DISCOVERY_PATHS:
                if url == 'http://t/' + path:
                    raise requests.ConnectionError('not found')
            body = 'base'
            if 'debug' in q:
                body += ' ' + q['debug']  # reflect the marker
            return _FakeResponse(text=body)

    session = _ReflectingSession()
    _install_fake_crawler(monkeypatch, pages, session)

    report = main_module.build_report('http://t', _args(discover_params=True,
                                                         param_wordlist=None,
                                                         param_probe_max_endpoints=10))
    params = _section(report, 'parameters')['rows']
    assert any(r['Parameter'] == 'debug' and r['Where'] == 'hidden (query)' for r in params)


def test_js_param_names_feed_the_active_probe(monkeypatch):
    # A parameter name that exists ONLY in JavaScript (searchParams.get) must
    # become a probe candidate and, if the endpoint reflects it, be reported.
    pages = [
        PageResult('http://t/', 200, 'http://t/', 'text/html', links=[],
                   scripts=['http://t/app.js'], headers={}),
    ]

    class _S(_FakeSession):
        def __init__(self):
            super().__init__({'http://t/app.js': _FakeResponse(
                text="const v = new URLSearchParams(location.search).get('sekrit');")})

        def get(self, url, timeout=None, headers=None):
            from urllib.parse import urlparse, parse_qsl
            for path in _DISCOVERY_PATHS:
                if url == 'http://t/' + path:
                    raise requests.ConnectionError('nf')
            if url == 'http://t/app.js':
                return self._responses[url]
            q = dict(parse_qsl(urlparse(url).query))
            body = 'base'
            if 'sekrit' in q:
                body += ' ' + q['sekrit']  # reflect it
            return _FakeResponse(text=body)

    _install_fake_crawler(monkeypatch, pages, _S())
    report = main_module.build_report('http://t', _args(discover_params=True,
                                                         param_methods='get',
                                                         param_wordlist=None,
                                                         param_probe_max_endpoints=5))
    params = _section(report, 'parameters')['rows']
    # It appears as a passive JS-observed param AND as a probed hidden one.
    assert any(r['Parameter'] == 'sekrit' and 'js' in r['Where'] for r in params)
    assert any(r['Parameter'] == 'sekrit' and r['Where'].startswith('hidden') for r in params)
