from __future__ import annotations
import requests

SECURITY_HEADERS = {
    'strict-transport-security': 'HSTS',
    'content-security-policy': 'CSP',
    'x-content-type-options': 'X-Content-Type-Options',
    'x-frame-options': 'X-Frame-Options',
    'referrer-policy': 'Referrer-Policy',
    'permissions-policy': 'Permissions-Policy',
}


def analyze_headers(url: str, headers: dict) -> dict:
    """Header/banner analysis from a plain {header_name: value} dict.

    This is the dict-based core so it can run either off a live
    requests.Response or off headers already captured by the crawler
    (avoiding a second HTTP request per page).
    """
    h = {k.lower(): v for k, v in headers.items()}
    missing = [name for key, name in SECURITY_HEADERS.items() if key not in h]
    return {
        'url': url,
        'security_headers_missing': missing,
        'cors': h.get('access-control-allow-origin'),
        'server': h.get('server'),
        'powered_by': h.get('x-powered-by'),
    }


def analyze_response(resp) -> dict:
    """Back-compat wrapper: analyze headers straight off a requests.Response,
    plus a coarse cookies_present flag. For per-cookie flag analysis use
    parse_cookies() instead -- resp.headers.get('set-cookie') collapses
    multiple Set-Cookie response headers into one comma-joined string, so it
    can only reliably answer "were any cookies set", not "what are they".
    """
    result = analyze_headers(resp.url, dict(resp.headers))
    cookies = [c.split(';', 1)[0] for c in resp.headers.get('set-cookie', '').splitlines() if c]
    result['cookies_present'] = bool(cookies)
    return result


def interesting_paths(base: str) -> list[str]:
    return [base.rstrip('/') + p for p in
            ['/robots.txt', '/sitemap.xml', '/swagger.json', '/openapi.json',
             '/swagger/index.html', '/api-docs']]


def parse_cookies(set_cookie_headers: list[str], url: str) -> list[dict]:
    """Parse a list of *individual* Set-Cookie header values (one string per
    header -- see crawler.spider.Crawler._set_cookie_headers, which is the
    correct way to obtain these from a requests.Response) into per-cookie
    flag findings.
    """
    cookies = []
    for line in set_cookie_headers:
        if not line:
            continue
        parts = [p.strip() for p in line.split(';')]
        if not parts or '=' not in parts[0]:
            continue
        name, _, value = parts[0].partition('=')
        flags = {p.lower() for p in parts[1:]}
        samesite = next(
            (p.split('=', 1)[1] for p in parts[1:] if p.lower().startswith('samesite=')),
            None,
        )
        secure = 'secure' in flags
        httponly = 'httponly' in flags
        cookies.append({
            'url': url,
            'name': name,
            'secure': secure,
            'httponly': httponly,
            'samesite': samesite,
            'issues': _cookie_issues(secure, httponly, samesite),
        })
    return cookies


def _cookie_issues(secure: bool, httponly: bool, samesite: str | None) -> list[str]:
    issues = []
    if not httponly:
        issues.append('Missing HttpOnly -- cookie is readable by client-side JavaScript')
    if not secure:
        issues.append('Missing Secure -- cookie can be sent over plaintext HTTP')
    if samesite and samesite.lower() == 'none' and not secure:
        issues.append('SameSite=None without Secure -- browsers require Secure whenever SameSite=None')
    return issues


def check_cors(session: requests.Session, url: str, timeout: float = 10,
               probe_origin: str = 'https://cors-probe.SentinelX.invalid') -> dict | None:
    """Send a request with a spoofed Origin header and inspect how the
    server responds. Returns None if the endpoint sets no CORS headers at
    all (nothing to report). A reflected arbitrary origin combined with
    Allow-Credentials: true is the worst-case misconfiguration.
    """
    try:
        r = session.get(url, timeout=timeout, headers={'Origin': probe_origin})
    except requests.RequestException as e:
        return {'url': url, 'error': str(e)}
    acao = r.headers.get('access-control-allow-origin')
    if not acao:
        return None
    acac = r.headers.get('access-control-allow-credentials')
    reflects_arbitrary_origin = acao == probe_origin
    return {
        'url': url,
        'access_control_allow_origin': acao,
        'access_control_allow_credentials': acac,
        'reflects_arbitrary_origin': reflects_arbitrary_origin,
        'wildcard': acao == '*',
        'high_risk': reflects_arbitrary_origin and (acac or '').lower() == 'true',
    }
