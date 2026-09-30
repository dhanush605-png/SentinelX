import requests
from requests.structures import CaseInsensitiveDict

from analysis.security import analyze_response, analyze_headers, interesting_paths, parse_cookies, check_cors


class _FakeResponse:
    def __init__(self, url, headers):
        self.url = url
        # requests.Response.headers is case-insensitive in real usage;
        # analyze_response relies on that, so the fake must match.
        self.headers = CaseInsensitiveDict(headers)


def test_reports_no_missing_headers_when_all_present():
    headers = {
        'Strict-Transport-Security': 'max-age=63072000',
        'Content-Security-Policy': "default-src 'self'",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=()',
    }
    result = analyze_response(_FakeResponse('https://example.com/', headers))
    assert result['security_headers_missing'] == []


def test_flags_all_missing_headers_when_none_present():
    result = analyze_response(_FakeResponse('https://example.com/', {}))
    assert set(result['security_headers_missing']) == {
        'HSTS', 'CSP', 'X-Content-Type-Options', 'X-Frame-Options',
        'Referrer-Policy', 'Permissions-Policy',
    }


def test_flags_partial_header_set():
    headers = {'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN'}
    result = analyze_response(_FakeResponse('https://example.com/', headers))
    assert 'HSTS' in result['security_headers_missing']
    assert 'CSP' in result['security_headers_missing']
    assert 'X-Content-Type-Options' not in result['security_headers_missing']


def test_detects_cookies_present():
    headers = {'Set-Cookie': 'session=abc123; HttpOnly\nother=1; Path=/'}
    result = analyze_response(_FakeResponse('https://example.com/', headers))
    assert result['cookies_present'] is True


def test_detects_no_cookies():
    result = analyze_response(_FakeResponse('https://example.com/', {}))
    assert result['cookies_present'] is False


def test_surfaces_cors_server_and_powered_by_headers():
    headers = {
        'Access-Control-Allow-Origin': '*',
        'Server': 'Apache/2.2.3 (CentOS)',
        'X-Powered-By': 'PHP/5.3.3',
    }
    result = analyze_response(_FakeResponse('https://example.com/', headers))
    assert result['cors'] == '*'
    assert result['server'] == 'Apache/2.2.3 (CentOS)'
    assert result['powered_by'] == 'PHP/5.3.3'


def test_interesting_paths_are_appended_to_base_and_slash_stripped():
    paths = interesting_paths('https://example.com/')
    assert paths[0] == 'https://example.com/robots.txt'
    assert 'https://example.com/sitemap.xml' in paths
    assert 'https://example.com/swagger.json' in paths
    assert all(not p.replace('https://example.com', '', 1).startswith('//') for p in paths)


# ---- analyze_headers (dict-based, used by main.py against crawler-captured headers) ----

def test_analyze_headers_is_case_insensitive_on_a_plain_dict():
    headers = {'x-content-type-options': 'nosniff', 'X-FRAME-OPTIONS': 'DENY'}
    result = analyze_headers('https://example.com/', headers)
    assert 'X-Content-Type-Options' not in result['security_headers_missing']
    assert 'X-Frame-Options' not in result['security_headers_missing']
    assert 'HSTS' in result['security_headers_missing']


# ---- parse_cookies -----------------------------------------------------

def test_parse_cookies_flags_missing_httponly_and_secure():
    cookies = parse_cookies(['tracking_id=abc; Path=/; SameSite=Lax'], 'https://example.com/')
    assert len(cookies) == 1
    c = cookies[0]
    assert c['name'] == 'tracking_id'
    assert c['secure'] is False
    assert c['httponly'] is False
    assert 'Missing HttpOnly' in c['issues'][0]
    assert any('Missing Secure' in i for i in c['issues'])


def test_parse_cookies_accepts_a_well_protected_cookie_with_no_issues():
    cookies = parse_cookies(['session=xyz; Secure; HttpOnly; SameSite=Strict'], 'https://example.com/')
    assert cookies[0]['secure'] is True
    assert cookies[0]['httponly'] is True
    assert cookies[0]['samesite'] == 'Strict'
    assert cookies[0]['issues'] == []


def test_parse_cookies_flags_samesite_none_without_secure():
    cookies = parse_cookies(['pref=dark; SameSite=None'], 'https://example.com/')
    assert any('SameSite=None without Secure' in i for i in cookies[0]['issues'])


def test_parse_cookies_handles_multiple_separate_header_values():
    # Each element is one Set-Cookie header value, as returned by
    # Crawler._set_cookie_headers() -- this is the case a naive
    # comma-joined/splitlines() parse gets wrong.
    cookies = parse_cookies(['a=1; HttpOnly', 'b=2; Secure'], 'https://example.com/')
    names = {c['name'] for c in cookies}
    assert names == {'a', 'b'}


def test_parse_cookies_returns_empty_list_for_no_cookies():
    assert parse_cookies([], 'https://example.com/') == []


# ---- check_cors ----------------------------------------------------------

class _FakeSession:
    def __init__(self, headers):
        self._headers = headers
        self.last_request_headers = None

    def get(self, url, timeout=None, headers=None):
        self.last_request_headers = headers
        return _FakeResponse(url, self._headers)


def test_check_cors_returns_none_when_no_cors_headers_present():
    session = _FakeSession({})
    assert check_cors(session, 'https://example.com/api') is None


def test_check_cors_flags_reflected_origin_with_credentials_as_high_risk():
    session = _FakeSession({
        'Access-Control-Allow-Origin': 'https://cors-probe.SentinelX.invalid',
        'Access-Control-Allow-Credentials': 'true',
    })
    result = check_cors(session, 'https://example.com/api')
    assert result['reflects_arbitrary_origin'] is True
    assert result['high_risk'] is True


def test_check_cors_wildcard_without_credentials_is_not_high_risk():
    session = _FakeSession({'Access-Control-Allow-Origin': '*'})
    result = check_cors(session, 'https://example.com/api')
    assert result['wildcard'] is True
    assert result['high_risk'] is False


def test_check_cors_strict_allowlist_is_not_flagged_high_risk():
    session = _FakeSession({'Access-Control-Allow-Origin': 'https://trusted.example.com'})
    result = check_cors(session, 'https://example.com/api')
    assert result['reflects_arbitrary_origin'] is False
    assert result['high_risk'] is False


def test_check_cors_surfaces_request_errors_instead_of_raising():
    class _RaisingSession:
        def get(self, *a, **k):
            raise requests.ConnectionError('boom')
    result = check_cors(_RaisingSession(), 'https://example.com/api')
    assert 'error' in result
