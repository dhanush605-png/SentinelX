import json

import pytest

from crawler.auth import parse_headers, parse_cookie_string, load_cookie_file, parse_basic_auth


def test_parse_headers_builds_a_dict():
    assert parse_headers(['Authorization: Bearer abc123', 'X-Api-Key: xyz']) == {
        'Authorization': 'Bearer abc123',
        'X-Api-Key': 'xyz',
    }


def test_parse_headers_returns_empty_dict_for_none_or_empty():
    assert parse_headers(None) == {}
    assert parse_headers([]) == {}


def test_parse_headers_rejects_missing_colon():
    with pytest.raises(ValueError):
        parse_headers(['not-a-header'])


def test_parse_cookie_string_parses_multiple_cookies():
    assert parse_cookie_string('session=abc; csrftoken=xyz') == {'session': 'abc', 'csrftoken': 'xyz'}


def test_parse_cookie_string_returns_empty_dict_for_none():
    assert parse_cookie_string(None) == {}


def test_load_cookie_file_reads_flat_map(tmp_path):
    f = tmp_path / 'cookies.json'
    f.write_text(json.dumps({'session': 'abc', 'csrftoken': 'xyz'}))
    assert load_cookie_file(str(f)) == {'session': 'abc', 'csrftoken': 'xyz'}


def test_load_cookie_file_reads_playwright_storage_state(tmp_path):
    f = tmp_path / 'state.json'
    f.write_text(json.dumps({
        'cookies': [
            {'name': 'session', 'value': 'abc', 'domain': 'example.com', 'path': '/'},
            {'name': 'csrftoken', 'value': 'xyz', 'domain': 'example.com', 'path': '/'},
        ],
        'origins': [],
    }))
    assert load_cookie_file(str(f)) == {'session': 'abc', 'csrftoken': 'xyz'}


def test_load_cookie_file_returns_empty_dict_for_none():
    assert load_cookie_file(None) == {}


def test_parse_basic_auth_splits_user_and_pass():
    assert parse_basic_auth('alice:hunter2') == ('alice', 'hunter2')


def test_parse_basic_auth_returns_none_for_none():
    assert parse_basic_auth(None) is None


def test_parse_basic_auth_rejects_missing_colon():
    with pytest.raises(ValueError):
        parse_basic_auth('no-colon-here')
