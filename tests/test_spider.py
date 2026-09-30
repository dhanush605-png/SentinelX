from crawler.spider import Crawler


def test_scope_same_origin_allows_same_scheme_and_host():
    c = Crawler('https://example.com', scope='same-origin')
    assert c.allowed('https://example.com/a')
    assert not c.allowed('https://example.org/a')


def test_scope_same_origin_rejects_different_scheme():
    c = Crawler('https://example.com', scope='same-origin')
    assert not c.allowed('http://example.com/a')


def test_scope_same_site_allows_subdomains():
    c = Crawler('https://example.com', scope='same-site')
    assert c.allowed('https://example.com/a')
    assert c.allowed('https://blog.example.com/a')
    assert not c.allowed('https://example.org/a')


def test_allowed_rejects_non_http_schemes():
    c = Crawler('https://example.com')
    assert not c.allowed('mailto:someone@example.com')
    assert not c.allowed('javascript:alert(1)')


def test_target_without_scheme_defaults_to_https():
    c = Crawler('example.com')
    assert c.target == 'https://example.com'
