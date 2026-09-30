"""Parameter discovery: passive enumeration of query/form parameters and
active hidden-parameter probing. The active probe is faked at the session
level (no real network) exactly like the rest of the suite."""
from crawler.spider import PageResult
from discovery.params import (
    parse_query_params, parse_fragment_params, extract_forms, collect_parameters,
    probe_hidden_params, load_param_wordlist, ParamObservation,
)

BASE = 'https://example.com/page'


# --- passive: query strings ------------------------------------------------

def test_parse_query_params_keeps_repeats_and_blanks():
    pairs = parse_query_params('https://x/y?a=1&a=2&b=&c')
    assert pairs == [('a', '1'), ('a', '2'), ('b', ''), ('c', '')]


def test_parse_query_params_empty_when_no_query():
    assert parse_query_params('https://x/y') == []


def test_parse_fragment_params_supports_spa_hash_route_query():
    assert parse_fragment_params('https://x/#/search?q=admin&sort=name') == [
        ('q', 'admin'), ('sort', 'name')
    ]


def test_parse_fragment_params_supports_query_hash_and_plain_hash_query():
    assert parse_fragment_params('https://x/#?q=admin') == [('q', 'admin')]
    assert parse_fragment_params('https://x/#q=admin&sort=name') == [
        ('q', 'admin'), ('sort', 'name')
    ]


def test_parse_fragment_params_ignores_route_only_fragment():
    assert parse_fragment_params('https://x/#/search') == []


# --- passive: forms --------------------------------------------------------

def test_extract_forms_resolves_action_method_and_named_fields():
    html = """
      <form action="/login" method="post">
        <input name="username" type="text">
        <input name="password" type="password">
        <input type="submit" value="Go">
      </form>
    """
    forms = extract_forms(html, BASE)
    assert len(forms) == 1
    f = forms[0]
    assert f.action == 'https://example.com/login'
    assert f.method == 'POST'
    names = {field.name for field in f.fields}
    assert names == {'username', 'password'}  # submit button excluded


def test_extract_forms_includes_select_and_textarea_and_defaults_method_get():
    html = """
      <form action="search">
        <input name="q" value="hello">
        <select name="category"><option>a</option></select>
        <textarea name="notes"></textarea>
      </form>
    """
    forms = extract_forms(html, BASE)
    f = forms[0]
    assert f.method == 'GET'
    assert f.action == 'https://example.com/search'
    assert {field.name for field in f.fields} == {'q', 'category', 'notes'}


def test_extract_forms_ignores_unnamed_fields():
    forms = extract_forms('<form><input type="text"></form>', BASE)
    assert forms[0].fields == []


# --- passive: aggregation across the crawl --------------------------------

def test_collect_parameters_merges_query_and_form_sources():
    form_html = '<form action="/submit" method="post"><input name="token"></form>'
    forms = extract_forms(form_html, 'https://example.com/')
    pages = [
        PageResult('https://example.com/list?page=2&sort=name', 200,
                   'https://example.com/list?page=2&sort=name', 'text/html',
                   links=['https://example.com/item?id=5'], forms=forms),
    ]
    inv = collect_parameters(pages)
    assert set(inv) == {'page', 'sort', 'id', 'token'}
    assert inv['page'].locations == {'query'}
    assert inv['page'].methods == {'GET'}
    assert '2' in inv['page'].example_values
    assert inv['token'].locations == {'form'}
    assert inv['token'].methods == {'POST'}
    assert 'https://example.com/submit' in inv['token'].endpoints
    # id came from a discovered link, not the page URL itself
    assert inv['id'].locations == {'query'}


def test_collect_parameters_discovers_fragment_parameters_from_links():
    pages = [
        PageResult('https://example.com/', 200, 'https://example.com/', 'text/html',
                   links=['https://example.com/#/search?q=RR_PARAM_PROBE&sort=name']),
    ]
    inv = collect_parameters(pages)
    assert {'q', 'sort'} <= set(inv)
    assert inv['q'].locations == {'fragment'}
    assert inv['q'].methods == {'CLIENT'}
    assert 'RR_PARAM_PROBE' in inv['q'].example_values
    assert 'https://example.com/#/search?q=RR_PARAM_PROBE&sort=name' in inv['q'].endpoints


def test_collect_parameters_example_values_are_capped():
    o = ParamObservation('p')
    for i in range(10):
        o.add_value(str(i))
    assert len(o.example_values) <= 3


# --- active: hidden-parameter probing -------------------------------------

class _Resp:
    def __init__(self, text='', status=200):
        self.text = text
        self.status_code = status


class _FakeSession:
    """Reflects any query parameter whose name is in `reflects` back into the
    body, so probe_hidden_params can detect it -- mimicking a server that
    echoes an accepted parameter's value."""
    def __init__(self, reflects=()):
        self.reflects = set(reflects)
        self.calls = []

    def get(self, url, timeout=None, headers=None):
        from urllib.parse import urlparse, parse_qsl
        self.calls.append(url)
        pairs = dict(parse_qsl(urlparse(url).query))
        body = 'baseline'
        for name, val in pairs.items():
            if name in self.reflects:
                body += f' echo={val}'
        return _Resp(text=body)


def test_probe_detects_reflected_hidden_parameter():
    session = _FakeSession(reflects={'debug'})
    results = probe_hidden_params(session, 'https://example.com/app',
                                  ['foo', 'debug', 'bar'], rate_limit=0.0)
    hits = {r.name for r in results if r.reflected}
    assert 'debug' in hits
    assert 'foo' not in hits and 'bar' not in hits


def test_probe_returns_nothing_when_no_candidates():
    assert probe_hidden_params(_FakeSession(), 'https://example.com/', []) == []


def test_probe_survives_a_failing_baseline():
    class _Broken:
        def get(self, *a, **k):
            raise RuntimeError('network down')
    # Must not raise -- a probe failure never aborts the scan.
    assert probe_hidden_params(_Broken(), 'https://x/', ['a']) == []


def test_load_param_wordlist_skips_blanks_and_comments(tmp_path):
    wl = tmp_path / 'w.txt'
    wl.write_text('id\n# a comment\n\npage\n', encoding='utf8')
    assert load_param_wordlist(str(wl)) == ['id', 'page']


def test_load_param_wordlist_none_returns_empty():
    assert load_param_wordlist(None) == []
