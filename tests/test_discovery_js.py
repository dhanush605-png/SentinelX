from discovery.js import extract_api_endpoints

BASE_URL = 'https://example.com/assets/app.js'


def test_extracts_absolute_api_url():
    script = "fetch('https://api.example.com/v1/users')"
    assert extract_api_endpoints(script, BASE_URL) == ['https://api.example.com/v1/users']


def test_extracts_and_resolves_relative_api_path():
    script = "axios.get('/api/v2/orders')"
    assert extract_api_endpoints(script, BASE_URL) == ['https://example.com/api/v2/orders']


def test_extracts_graphql_swagger_and_openapi_paths():
    script = """
        const a = "/graphql";
        const b = '/swagger/index.html';
        const c = `/openapi.json`;
    """
    result = extract_api_endpoints(script, BASE_URL)
    assert result == sorted([
        'https://example.com/graphql',
        'https://example.com/swagger/index.html',
        'https://example.com/openapi.json',
    ])


def test_ignores_urls_that_do_not_look_like_api_endpoints():
    script = "const cdn = 'https://cdn.example.com/logo.png'; const home = '/about';"
    assert extract_api_endpoints(script, BASE_URL) == []


def test_deduplicates_repeated_endpoints():
    script = "fetch('/api/users'); fetch('/api/users');"
    assert extract_api_endpoints(script, BASE_URL) == ['https://example.com/api/users']


def test_returns_empty_list_for_script_with_no_urls():
    assert extract_api_endpoints("console.log('no urls here');", BASE_URL) == []
