"""The enhanced JS analysis: endpoints that are NOT written as a single
quoted literal -- template literals, string concatenation, and source
maps. The original extract_api_endpoints behavior is covered by
test_discovery_js.py and must remain unchanged."""
import json

from discovery.js import analyze_script, endpoints_from_source_map, extract_api_endpoints

BASE = 'https://example.com/assets/app.js'


def test_template_literal_api_endpoint_is_recovered_with_placeholder():
    script = "const u = `${API_BASE}/api/v1/users/${userId}`;"
    a = analyze_script(script, BASE)
    assert '{}/api/v1/users/{}' in a.template_endpoints
    # It's API-shaped, so it also surfaces via all_api.
    assert '{}/api/v1/users/{}' in a.all_api


def test_rooted_template_literal_is_resolved_against_base():
    script = "fetch(`/api/orders/${id}`)"
    a = analyze_script(script, BASE)
    assert 'https://example.com/api/orders/{}' in a.template_endpoints


def test_string_concatenation_fragment_is_surfaced_as_path_candidate():
    # base + '/users/' + id : only '/users/' is a literal, and it is NOT
    # API-marker-shaped, so extract_api_endpoints misses it entirely.
    script = "const url = base + '/users/' + id;"
    assert extract_api_endpoints(script, BASE) == []
    a = analyze_script(script, BASE)
    assert 'https://example.com/users/' in a.path_candidates


def test_non_api_path_literal_is_a_candidate_not_an_api_endpoint():
    script = "const home = '/dashboard/settings';"
    a = analyze_script(script, BASE)
    assert 'https://example.com/dashboard/settings' in a.path_candidates
    assert a.api_endpoints == []


def test_literal_api_endpoints_still_work_and_match_legacy_extractor():
    script = "axios.get('/api/v2/orders'); fetch('https://api.example.com/api/things')"
    a = analyze_script(script, BASE)
    assert a.api_endpoints == extract_api_endpoints(script, BASE)
    assert 'https://example.com/api/v2/orders' in a.api_endpoints


def test_source_mapping_url_is_detected_and_resolved():
    script = "console.log(1);\n//# sourceMappingURL=app.js.map"
    a = analyze_script(script, BASE)
    assert a.source_map_url == 'https://example.com/assets/app.js.map'


def test_inline_data_uri_source_map_is_not_treated_as_a_fetchable_url():
    script = "x=1;\n//# sourceMappingURL=data:application/json;base64,eyJ2IjozfQ=="
    a = analyze_script(script, BASE)
    assert a.source_map_url is None


def test_endpoints_from_source_map_mines_embedded_original_source():
    map_text = json.dumps({
        'version': 3,
        'sources': ['src/api/client.js', 'src/util.js'],
        'sourcesContent': [
            "export const users = () => fetch('/api/v3/users');",
            "export const noop = () => '/static/logo.png';",
        ],
    })
    mined = endpoints_from_source_map(map_text, 'https://example.com/app.js.map')
    assert 'src/api/client.js' in mined['sources']
    assert 'https://example.com/api/v3/users' in mined['api_endpoints']


def test_endpoints_from_source_map_handles_invalid_json():
    mined = endpoints_from_source_map('not json{', 'https://example.com/x.map')
    assert mined == {'sources': [], 'api_endpoints': [], 'path_candidates': []}


def test_interpolated_literal_is_not_emitted_as_a_concrete_endpoint():
    # A back-tick template must not leak into api_endpoints as a bogus URL
    # containing '${id}' -- only its normalized {} template form is kept.
    script = "fetch(`/api/v2/orders/${id}`)"
    a = analyze_script(script, BASE)
    assert not any('${' in e for e in a.api_endpoints)
    assert not any('${' in e for e in a.all_api)
    assert 'https://example.com/api/v2/orders/{}' in a.template_endpoints


# --- JavaScript -> parameter-name extraction (feature: JS -> params) ------

def test_extract_param_names_from_searchparams_and_getparam():
    from discovery.js import extract_param_names_from_js
    script = """
      const p = new URLSearchParams(location.search);
      const a = p.get('userId');
      if (params.has('debug')) {}
      const t = getQueryParam('trace_id');
    """
    names = extract_param_names_from_js(script)
    assert {'userId', 'debug', 'trace_id'} <= names


def test_extract_param_names_from_query_literals_and_appends():
    from discovery.js import extract_param_names_from_js
    script = """
      fetch('/search?q=hi&page=3');
      const fd = new FormData(); fd.append('avatar_id', x);
      const u = `/api/items?active=${flag}&sort=name`;
    """
    names = extract_param_names_from_js(script)
    assert {'q', 'page', 'avatar_id', 'active', 'sort'} <= names


def test_extract_param_names_is_empty_for_plain_script():
    from discovery.js import extract_param_names_from_js
    assert extract_param_names_from_js("console.log('hello world');") == set()


# --- JavaScript -> fragment parameter extraction (hash literals) ----------

def test_extract_param_names_from_quoted_hash_route_literal():
    from discovery.js import extract_param_names_from_js
    script = "navigate('#/search?q=admin&sort=name');"
    names = extract_param_names_from_js(script)
    assert {'q', 'sort'} <= names


def test_extract_param_names_from_hash_assignment_and_query_hash():
    from discovery.js import extract_param_names_from_js
    script = "location.hash = '#tab=info'; router.route(\"#?debug=1\", handler);"
    names = extract_param_names_from_js(script)
    assert {'tab', 'debug'} <= names


def test_extract_param_names_from_hash_template_literal():
    from discovery.js import extract_param_names_from_js
    script = "const url = `#/search?q=${term}&page=${p}`;"
    names = extract_param_names_from_js(script)
    assert {'q', 'page'} <= names


def test_extract_param_names_ignores_route_only_and_non_param_hashes():
    from discovery.js import extract_param_names_from_js
    # A route-only hash, a bare anchor, and a CSS hex color all start with
    # '#' but carry no query-like data, so none should yield spurious names.
    script = """
      navigate('#/dashboard');
      const link = '#top';
      const style = { color: '#fff', border: '#a1b2c3' };
    """
    names = extract_param_names_from_js(script)
    assert names == set()
